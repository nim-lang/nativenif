## RV32 encoder self-test: build ONE bare-metal image that computes a list of
## expressions and compares each against its expected value, exiting with the
## 1-based index of the first mismatch (0 = every check passed).
##
## The twin of `thumb2_selftest.nim`, and for the same reason: QEMU ships no
## disassembler in this configuration, but its DECODER is the one that will
## execute whatever the backend emits, so "the result is right" checks the
## encoding at exactly the level that matters. It also exercises the branch
## encoders, the `auipc`/`lui` address pairs and the relocation patcher, none of
## which a byte-comparison could reach.
##
## Run:  nim r tests/rv32_selftest.nim out.elf
##       qemu-system-riscv32 -M virt -bios none -semihosting-config enable=on \
##                           -display none -kernel out.elf
##
## `a0` holds each check's computed value. `s1` (x9) holds the 1-based index of
## the check being run, so the failure path reports WHICH one broke with no
## per-check code — and `s1` is callee-saved, which matters because some checks
## make calls.

import std / [os, strutils]
import "../src/nifasm/rv32/encoder"
import "../src/nifasm/core/buffers"
import "../src/nifasm/core/relocs"
import "../src/nifasm/image/elf32"

type Check = object
  name: string
  emit: proc (b: var Buffer) {.closure.}   ## leave the computed value in a0
  want: uint32

var checks: seq[Check] = @[]
proc check(name: string; want: uint32; emit: proc (b: var Buffer) {.closure.}) =
  checks.add Check(name: name, emit: emit, want: want)

# ── constant materialization ────────────────────────────────────────────────
# `emitLi`'s hi/lo split is the single most consequential routine in the encoder
# (see `splitHiLo`), so it is tested at the boundaries that expose a missing
# round-up rather than at round numbers that cannot.

check "li small positive", 7:
  (proc (b: var Buffer) = b.data.emitLi(A0, 7))
check "li 2047 (largest imm12)", 2047:
  (proc (b: var Buffer) = b.data.emitLi(A0, 2047))
check "li 2048 (first lui+addi)", 2048:
  (proc (b: var Buffer) = b.data.emitLi(A0, 2048))
check "li negative", 0xFFFFFFF6'u32:
  (proc (b: var Buffer) = b.data.emitLi(A0, 0xFFFFFFF6'u32))
check "li -2048 (smallest imm12)", 0xFFFFF800'u32:
  (proc (b: var Buffer) = b.data.emitLi(A0, 0xFFFFF800'u32))
check "li 0x800 low part forces hi round-up", 0x12345800'u32:
  (proc (b: var Buffer) = b.data.emitLi(A0, 0x12345800'u32))
check "li 0xFFF low part", 0x12345FFF'u32:
  (proc (b: var Buffer) = b.data.emitLi(A0, 0x12345FFF'u32))
check "li 0x7FF low part (no round-up)", 0x123457FF'u32:
  (proc (b: var Buffer) = b.data.emitLi(A0, 0x123457FF'u32))
check "li page-aligned (addi elided)", 0xDEAD0000'u32:
  (proc (b: var Buffer) = b.data.emitLi(A0, 0xDEAD0000'u32))
check "li full 32-bit", 0xDEADBEEF'u32:
  (proc (b: var Buffer) = b.data.emitLi(A0, 0xDEADBEEF'u32))
check "lui alone", 0x000FF000'u32:
  (proc (b: var Buffer) = b.data.emitLui(A0, 0xFF))
check "mv", 0x99:
  (proc (b: var Buffer) = b.data.emitLi(T0, 0x99); b.data.emitMv(A0, T0))
check "x0 reads as zero", 0:
  (proc (b: var Buffer) = b.data.emitAddi(A0, X0, 0))
check "writes to x0 are discarded", 5:
  (proc (b: var Buffer) =
    b.data.emitLi(A0, 5); b.data.emitLi(X0, 999); b.data.emitAdd(A0, A0, X0))

# ── register-immediate ALU ──────────────────────────────────────────────────

check "addi", 15:
  (proc (b: var Buffer) = b.data.emitLi(A0, 10); b.data.emitAddi(A0, A0, 5))
check "addi negative", 5:
  (proc (b: var Buffer) = b.data.emitLi(A0, 10); b.data.emitAddi(A0, A0, -5))
check "andi", 0x0F:
  (proc (b: var Buffer) = b.data.emitLi(A0, 0xFF); b.data.emitAndi(A0, A0, 0x0F))
check "ori", 0xF0:
  (proc (b: var Buffer) = b.data.emitLi(A0, 0xA0); b.data.emitOri(A0, A0, 0x50))
check "xori", 0xFF:
  (proc (b: var Buffer) = b.data.emitLi(A0, 0x0F); b.data.emitXori(A0, A0, 0xF0))
check "slti signed true", 1:
  (proc (b: var Buffer) = b.data.emitLi(A0, 0xFFFFFFFF'u32); b.data.emitSlti(A0, A0, 0))
check "sltiu treats -1 as huge", 0:
  (proc (b: var Buffer) = b.data.emitLi(A0, 0xFFFFFFFF'u32); b.data.emitSltiu(A0, A0, 1))
check "slli", 0x100:
  (proc (b: var Buffer) = b.data.emitLi(A0, 1); b.data.emitSlli(A0, A0, 8))
check "srli is logical", 0x00FFFFFF'u32:
  (proc (b: var Buffer) = b.data.emitLi(A0, 0xFFFFFFFF'u32); b.data.emitSrli(A0, A0, 8))
check "srai is arithmetic", 0xFFFFFFFF'u32:
  (proc (b: var Buffer) = b.data.emitLi(A0, 0xFFFFFFFF'u32); b.data.emitSrai(A0, A0, 8))
check "slli 31 (max shift)", 0x80000000'u32:
  (proc (b: var Buffer) = b.data.emitLi(A0, 1); b.data.emitSlli(A0, A0, 31))

# ── register-register ALU ───────────────────────────────────────────────────

check "add", 30:
  (proc (b: var Buffer) =
    b.data.emitLi(T0, 10); b.data.emitLi(T1, 20); b.data.emitAdd(A0, T0, T1))
check "sub", 12:
  (proc (b: var Buffer) =
    b.data.emitLi(T0, 20); b.data.emitLi(T1, 8); b.data.emitSub(A0, T0, T1))
check "and", 0x0F00:
  (proc (b: var Buffer) =
    b.data.emitLi(T0, 0xFF00); b.data.emitLi(T1, 0x0FFF); b.data.emitAnd(A0, T0, T1))
check "or", 0xFFFF:
  (proc (b: var Buffer) =
    b.data.emitLi(T0, 0xFF00); b.data.emitLi(T1, 0x00FF); b.data.emitOr(A0, T0, T1))
check "xor", 0xF0F0:
  (proc (b: var Buffer) =
    b.data.emitLi(T0, 0xFFFF); b.data.emitLi(T1, 0x0F0F); b.data.emitXor(A0, T0, T1))
check "sll by register", 0x1000:
  (proc (b: var Buffer) =
    b.data.emitLi(T0, 1); b.data.emitLi(T1, 12); b.data.emitSll(A0, T0, T1))
check "srl by register", 0x000FFFFF'u32:
  (proc (b: var Buffer) =
    b.data.emitLi(T0, 0xFFFFFFFF'u32); b.data.emitLi(T1, 12); b.data.emitSrl(A0, T0, T1))
check "sra by register", 0xFFFFFFFF'u32:
  (proc (b: var Buffer) =
    b.data.emitLi(T0, 0xFFFFFFFF'u32); b.data.emitLi(T1, 12); b.data.emitSra(A0, T0, T1))
check "shift uses only the low 5 bits", 2:
  (proc (b: var Buffer) =
    b.data.emitLi(T0, 1); b.data.emitLi(T1, 33); b.data.emitSll(A0, T0, T1))
check "slt signed", 1:
  (proc (b: var Buffer) =
    b.data.emitLi(T0, 0xFFFFFFFF'u32); b.data.emitLi(T1, 1); b.data.emitSlt(A0, T0, T1))
check "sltu unsigned disagrees with slt", 0:
  (proc (b: var Buffer) =
    b.data.emitLi(T0, 0xFFFFFFFF'u32); b.data.emitLi(T1, 1); b.data.emitSltu(A0, T0, T1))
check "neg", 0xFFFFFFF6'u32:
  (proc (b: var Buffer) = b.data.emitLi(T0, 10); b.data.emitNeg(A0, T0))
check "not", 0xFFFFFF00'u32:
  (proc (b: var Buffer) = b.data.emitLi(T0, 0xFF); b.data.emitNot(A0, T0))
check "seqz true", 1:
  (proc (b: var Buffer) = b.data.emitLi(T0, 0); b.data.emitSeqz(A0, T0))
check "seqz false", 0:
  (proc (b: var Buffer) = b.data.emitLi(T0, 7); b.data.emitSeqz(A0, T0))
check "snez true", 1:
  (proc (b: var Buffer) = b.data.emitLi(T0, 7); b.data.emitSnez(A0, T0))

# ── RV32M ───────────────────────────────────────────────────────────────────

check "mul", 72:
  (proc (b: var Buffer) =
    b.data.emitLi(T0, 8); b.data.emitLi(T1, 9); b.data.emitMul(A0, T0, T1))
check "mul keeps the low word", 0x00000000'u32:
  (proc (b: var Buffer) =
    b.data.emitLi(T0, 0x10000000'u32); b.data.emitLi(T1, 16); b.data.emitMul(A0, T0, T1))
check "mulhu gives the high word", 1:
  (proc (b: var Buffer) =
    b.data.emitLi(T0, 0x10000000'u32); b.data.emitLi(T1, 16); b.data.emitMulhu(A0, T0, T1))
check "mulh is signed", 0xFFFFFFFF'u32:
  (proc (b: var Buffer) =
    b.data.emitLi(T0, 0xFFFFFFFF'u32)          # -1
    b.data.emitLi(T1, 2)
    b.data.emitMulh(A0, T0, T1))               # high word of -2
check "div truncates toward zero", 0xFFFFFFFD'u32:
  (proc (b: var Buffer) =
    b.data.emitLi(T0, 0xFFFFFFF6'u32)          # -10
    b.data.emitLi(T1, 3)
    b.data.emitDiv(A0, T0, T1))                # -10 / 3 == -3
check "divu", 33:
  (proc (b: var Buffer) =
    b.data.emitLi(T0, 100); b.data.emitLi(T1, 3); b.data.emitDivu(A0, T0, T1))
check "rem takes the dividend's sign", 0xFFFFFFFF'u32:
  (proc (b: var Buffer) =
    b.data.emitLi(T0, 0xFFFFFFF7'u32)          # -9
    b.data.emitLi(T1, 2)
    b.data.emitRem(A0, T0, T1))                # -1, not +1
check "remu", 1:
  (proc (b: var Buffer) =
    b.data.emitLi(T0, 100); b.data.emitLi(T1, 3); b.data.emitRemu(A0, T0, T1))
check "div by zero yields all-ones, does not trap", 0xFFFFFFFF'u32:
  (proc (b: var Buffer) =
    b.data.emitLi(T0, 42); b.data.emitLi(T1, 0); b.data.emitDiv(A0, T0, T1))

# ── loads and stores ────────────────────────────────────────────────────────
# Every one works on the stack, so the image needs no writable data section.

check "sw/lw round-trip", 0xDEADBEEF'u32:
  (proc (b: var Buffer) =
    b.data.emitAddi(Sp, Sp, -16)
    b.data.emitLi(T0, 0xDEADBEEF'u32)
    b.data.emitSw(T0, Sp, 0)
    b.data.emitLw(A0, Sp, 0)
    b.data.emitAddi(Sp, Sp, 16))
check "sw/lw at a non-zero offset", 0x11223344'u32:
  (proc (b: var Buffer) =
    b.data.emitAddi(Sp, Sp, -16)
    b.data.emitLi(T0, 0x11223344'u32)
    b.data.emitSw(T0, Sp, 8)
    b.data.emitLw(A0, Sp, 8)
    b.data.emitAddi(Sp, Sp, 16))
check "sb writes ONE byte", 0xDEADBE55'u32:
  (proc (b: var Buffer) =
    b.data.emitAddi(Sp, Sp, -16)
    b.data.emitLi(T0, 0xDEADBEEF'u32)
    b.data.emitSw(T0, Sp, 0)
    b.data.emitLi(T1, 0x55)
    b.data.emitSb(T1, Sp, 0)
    b.data.emitLw(A0, Sp, 0)
    b.data.emitAddi(Sp, Sp, 16))
check "sh writes ONE halfword", 0xDEAD1234'u32:
  (proc (b: var Buffer) =
    b.data.emitAddi(Sp, Sp, -16)
    b.data.emitLi(T0, 0xDEADBEEF'u32)
    b.data.emitSw(T0, Sp, 0)
    b.data.emitLi(T1, 0x1234)
    b.data.emitSh(T1, Sp, 0)
    b.data.emitLw(A0, Sp, 0)
    b.data.emitAddi(Sp, Sp, 16))
check "lbu zero-extends", 0xEF:
  (proc (b: var Buffer) =
    b.data.emitAddi(Sp, Sp, -16)
    b.data.emitLi(T0, 0xDEADBEEF'u32)
    b.data.emitSw(T0, Sp, 0)
    b.data.emitLbu(A0, Sp, 0)
    b.data.emitAddi(Sp, Sp, 16))
check "lb sign-extends", 0xFFFFFFEF'u32:
  (proc (b: var Buffer) =
    b.data.emitAddi(Sp, Sp, -16)
    b.data.emitLi(T0, 0xDEADBEEF'u32)
    b.data.emitSw(T0, Sp, 0)
    b.data.emitLb(A0, Sp, 0)
    b.data.emitAddi(Sp, Sp, 16))
check "lhu zero-extends", 0xBEEF:
  (proc (b: var Buffer) =
    b.data.emitAddi(Sp, Sp, -16)
    b.data.emitLi(T0, 0xDEADBEEF'u32)
    b.data.emitSw(T0, Sp, 0)
    b.data.emitLhu(A0, Sp, 0)
    b.data.emitAddi(Sp, Sp, 16))
check "lh sign-extends", 0xFFFFBEEF'u32:
  (proc (b: var Buffer) =
    b.data.emitAddi(Sp, Sp, -16)
    b.data.emitLi(T0, 0xDEADBEEF'u32)
    b.data.emitSw(T0, Sp, 0)
    b.data.emitLh(A0, Sp, 0)
    b.data.emitAddi(Sp, Sp, 16))
check "store at a negative offset", 0xCAFEBABE'u32:
  (proc (b: var Buffer) =
    b.data.emitAddi(Sp, Sp, -16)
    b.data.emitAddi(T2, Sp, 16)
    b.data.emitLi(T0, 0xCAFEBABE'u32)
    b.data.emitSw(T0, T2, -16)
    b.data.emitLw(A0, Sp, 0)
    b.data.emitAddi(Sp, Sp, 16))

# ── branches, jumps and the relocation patcher ──────────────────────────────
# The `want` values are chosen so that BOTH outcomes of every branch are
# distinguishable: a branch that never fires and one that always fires give
# different wrong answers, so a broken condition cannot pass by accident.

template branchCheck(nm: string; c: BranchCond; lhs, rhs: uint32; taken: bool) =
  check nm, (if taken: 1'u32 else: 0'u32):
    (proc (b: var Buffer) =
      let lTaken = b.createLabel()
      let lDone = b.createLabel()
      b.data.emitLi(T0, lhs)
      b.data.emitLi(T1, rhs)
      b.emitBranch(c, T0, T1, lTaken)
      b.data.emitLi(A0, 0)
      b.emitJ(lDone)
      b.defineLabel(lTaken)
      b.data.emitLi(A0, 1)
      b.defineLabel(lDone))

branchCheck("beq taken", Beq, 5, 5, true)
branchCheck("beq not taken", Beq, 5, 6, false)
branchCheck("bne taken", Bne, 5, 6, true)
branchCheck("bne not taken", Bne, 5, 5, false)
branchCheck("blt signed taken", Blt, 0xFFFFFFFF'u32, 1, true)
branchCheck("blt signed not taken", Blt, 1, 0xFFFFFFFF'u32, false)
branchCheck("bge taken on equal", Bge, 7, 7, true)
branchCheck("bge signed not taken", Bge, 0xFFFFFFFF'u32, 1, false)
branchCheck("bltu disagrees with blt", Bltu, 0xFFFFFFFF'u32, 1, false)
branchCheck("bgeu taken", Bgeu, 0xFFFFFFFF'u32, 1, true)

check "backward branch closes a loop", 55:
  (proc (b: var Buffer) =
    # sum 1..10 — a backward `bne`, which is the negative-displacement half of
    # the B-type patcher that a forward-only test never reaches.
    let lTop = b.createLabel()
    b.data.emitLi(A0, 0)          # acc
    b.data.emitLi(T0, 1)          # i
    b.data.emitLi(T1, 11)         # limit
    b.defineLabel(lTop)
    b.data.emitAdd(A0, A0, T0)
    b.data.emitAddi(T0, T0, 1)
    b.emitBranch(Bne, T0, T1, lTop))

check "jal/ret round-trip", 42:
  (proc (b: var Buffer) =
    let lFn = b.createLabel()
    let lAfter = b.createLabel()
    b.emitJ(lAfter)               # jump over the callee
    b.defineLabel(lFn)
    b.data.emitLi(A0, 42)
    b.data.emitRet()
    b.defineLabel(lAfter)
    # `ra` is clobbered by the call, which is exactly why the harness keeps the
    # check index in the callee-saved `s1` rather than in a temporary.
    b.emitJal(lFn))

check "jal writes the return address", 1:
  (proc (b: var Buffer) =
    let lFn = b.createLabel()
    let lAfter = b.createLabel()
    b.emitJ(lAfter)
    b.defineLabel(lFn)
    b.data.emitMv(A0, Ra)         # hand the return address back
    b.data.emitRet()
    b.defineLabel(lAfter)
    b.emitJal(lFn)
    # It must point at the instruction AFTER the `jal`, so it is non-zero and
    # 4-aligned. Reduce to a boolean the check can compare.
    b.data.emitSnez(A0, A0))

check "la reaches a forward label", 1:
  (proc (b: var Buffer) =
    # `auipc`+`addi` against a label ahead of it: the address must equal the
    # label's own, which is what comparing against a second `la` proves without
    # the test needing to know the load address.
    let lHere = b.createLabel()
    b.emitLa(A0, lHere)
    b.defineLabel(lHere)
    b.emitLa(T0, lHere)
    b.data.emitSub(A0, A0, T0)
    b.data.emitSeqz(A0, A0))

check "la of a backward label yields its real address", 16:
  (proc (b: var Buffer) =
    # The label, then two 8-byte `auipc`+`addi` pairs, then a bare `auipc` — whose
    # own address is therefore exactly 16 bytes past the label. Subtracting the
    # backward-resolved `la` from it must give that 16 and nothing else.
    let lTop = b.createLabel()
    b.defineLabel(lTop)
    b.emitLa(T0, lTop)
    b.emitLa(T1, lTop)
    b.data.emitAuipc(A0, 0)
    b.data.emitSub(A0, A0, T0))

check "two `la`s of one label from different PCs agree", 1:
  (proc (b: var Buffer) =
    # The property a fixed-base patcher would break: both pairs name the same
    # label from DIFFERENT addresses, so each `auipc` must contribute its own PC.
    # The `nop` between them makes the two sites differ by a non-multiple of 8,
    # so even a half-right base shows up.
    let lTop = b.createLabel()
    b.defineLabel(lTop)
    b.emitLa(T0, lTop)
    b.data.emitNop()
    b.emitLa(T1, lTop)
    b.data.emitSub(A0, T0, T1)
    b.data.emitSeqz(A0, A0))

check "la across a hi/lo boundary", 1:
  (proc (b: var Buffer) =
    # `splitHiLo`'s round-up rule, exercised through the PC-relative patcher
    # rather than through `emitLi`: pad the distance so the low 12 bits of the
    # displacement land above 0x800, where a missing `+ 0x800` is off by 4096.
    let lTop = b.createLabel()
    b.defineLabel(lTop)
    b.emitLa(T0, lTop)
    for _ in 0 ..< 520: b.data.emitNop()      # 2080 bytes: lo12 crosses 0x800
    b.emitLa(T1, lTop)
    b.data.emitSub(A0, T0, T1)
    b.data.emitSeqz(A0, A0))

check "load through an la'd address", 0x5A5A5A5A'u32:
  (proc (b: var Buffer) =
    let lData = b.createLabel()
    let lAfter = b.createLabel()
    b.emitJ(lAfter)               # step over the inline constant
    b.defineLabel(lData)
    b.data.addUint32 0x5A5A5A5A'u32
    b.defineLabel(lAfter)
    b.emitLa(T0, lData)
    b.data.emitLw(A0, T0, 0))

# ── fences ──────────────────────────────────────────────────────────────────

check "fence computes nothing and breaks nothing", 5:
  (proc (b: var Buffer) = b.data.emitLi(A0, 5); b.data.emitFence())
check "fence.i computes nothing and breaks nothing", 6:
  (proc (b: var Buffer) = b.data.emitLi(A0, 6); b.data.emitFenceI())

# ── RV32A ───────────────────────────────────────────────────────────────────

check "lr.w reads the cell", 0xDEADBEEF'u32:
  (proc (b: var Buffer) =
    b.data.emitAddi(Sp, Sp, -16)
    b.data.emitLi(T0, 0xDEADBEEF'u32)
    b.data.emitSw(T0, Sp, 0)
    b.data.emitMv(T1, Sp)
    b.data.emitLrW(A0, T1))
check "sc.w after lr.w succeeds (0) and stores", 0x11223344'u32:
  (proc (b: var Buffer) =
    b.data.emitAddi(Sp, Sp, -16)
    b.data.emitLi(T0, 0xDEADBEEF'u32)
    b.data.emitSw(T0, Sp, 0)
    b.data.emitMv(T1, Sp)
    b.data.emitLrW(T2, T1)
    b.data.emitLi(T0, 0x11223344'u32)
    b.data.emitScW(T3, T1, T0)
    b.data.emitLw(A0, Sp, 0)
    b.data.emitAddi(Sp, Sp, 16))
check "sc.w reports success as 0", 0:
  (proc (b: var Buffer) =
    b.data.emitAddi(Sp, Sp, -16)
    b.data.emitMv(T1, Sp)
    b.data.emitLrW(T2, T1)
    b.data.emitLi(T0, 1)
    b.data.emitScW(A0, T1, T0)
    b.data.emitAddi(Sp, Sp, 16))
check "amoswap.w returns the OLD value", 0xDEADBEEF'u32:
  (proc (b: var Buffer) =
    b.data.emitAddi(Sp, Sp, -16)
    b.data.emitLi(T0, 0xDEADBEEF'u32)
    b.data.emitSw(T0, Sp, 0)
    b.data.emitMv(T1, Sp)
    b.data.emitLi(T2, 0x99)
    b.data.emitAmoswapW(A0, T1, T2)
    b.data.emitAddi(Sp, Sp, 16))
check "amoadd.w stores the SUM", 30:
  (proc (b: var Buffer) =
    b.data.emitAddi(Sp, Sp, -16)
    b.data.emitLi(T0, 10)
    b.data.emitSw(T0, Sp, 0)
    b.data.emitMv(T1, Sp)
    b.data.emitLi(T2, 20)
    b.data.emitAmoaddW(T3, T1, T2)
    b.data.emitLw(A0, Sp, 0)
    b.data.emitAddi(Sp, Sp, 16))

# ── RV32F / RV32D ───────────────────────────────────────────────────────────
# Floats reach `a0` through `fmv.x.w` (single) or a store/load pair (double, for
# which RV32 has no register move at all — see `emitFmvXW`). Every expected value
# is the IEEE bit pattern, so a wrong `fmt` field shows up as a wrong answer
# rather than as an approximately-right one.

const
  F1_0  = 0x3F800000'u32   ## 1.0f
  F2_0  = 0x40000000'u32   ## 2.0f
  F3_0  = 0x40400000'u32   ## 3.0f
  F6_0  = 0x40C00000'u32   ## 6.0f
  F0_5  = 0x3F000000'u32   ## 0.5f
  FM1_0 = 0xBF800000'u32   ## -1.0f

proc loadF(b: var Buffer; f: FloatRegister; bits: uint32) =
  ## A single-precision constant into an FP register, via a GPR.
  b.data.emitLi(T0, bits)
  b.data.emitFmvWX(f, T0)

check "fmv.w.x / fmv.x.w round-trip", F1_0:
  (proc (b: var Buffer) =
    b.loadF(F0, F1_0)
    b.data.emitFmvXW(A0, F0))
check "fadd.s", F3_0:
  (proc (b: var Buffer) =
    b.loadF(F0, F1_0); b.loadF(F1, F2_0)
    b.data.emitFadd(F2, F0, F1, FpS)
    b.data.emitFmvXW(A0, F2))
check "fsub.s", F1_0:
  (proc (b: var Buffer) =
    b.loadF(F0, F3_0); b.loadF(F1, F2_0)
    b.data.emitFsub(F2, F0, F1, FpS)
    b.data.emitFmvXW(A0, F2))
check "fmul.s", F6_0:
  (proc (b: var Buffer) =
    b.loadF(F0, F2_0); b.loadF(F1, F3_0)
    b.data.emitFmul(F2, F0, F1, FpS)
    b.data.emitFmvXW(A0, F2))
check "fdiv.s", F0_5:
  (proc (b: var Buffer) =
    b.loadF(F0, F1_0); b.loadF(F1, F2_0)
    b.data.emitFdiv(F2, F0, F1, FpS)
    b.data.emitFmvXW(A0, F2))
check "fneg.s flips only the sign bit", FM1_0:
  (proc (b: var Buffer) =
    b.loadF(F0, F1_0)
    b.data.emitFneg(F1, F0, FpS)
    b.data.emitFmvXW(A0, F1))
check "fabs.s clears it", F1_0:
  (proc (b: var Buffer) =
    b.loadF(F0, FM1_0)
    b.data.emitFabs(F1, F0, FpS)
    b.data.emitFmvXW(A0, F1))
check "fmv.s copies", F2_0:
  (proc (b: var Buffer) =
    b.loadF(F0, F2_0)
    b.data.emitFmv(F1, F0, FpS)
    b.data.emitFmvXW(A0, F1))
check "fsqrt.s", F2_0:
  (proc (b: var Buffer) =
    b.loadF(F0, 0x40800000'u32)       # 4.0f
    b.data.emitFsqrt(F1, F0, FpS)
    b.data.emitFmvXW(A0, F1))
check "fmin.s", F1_0:
  (proc (b: var Buffer) =
    b.loadF(F0, F1_0); b.loadF(F1, F2_0)
    b.data.emitFmin(F2, F0, F1, FpS)
    b.data.emitFmvXW(A0, F2))
check "fmax.s", F2_0:
  (proc (b: var Buffer) =
    b.loadF(F0, F1_0); b.loadF(F1, F2_0)
    b.data.emitFmax(F2, F0, F1, FpS)
    b.data.emitFmvXW(A0, F2))
check "feq.s writes a GPR, not a flag", 1:
  (proc (b: var Buffer) =
    b.loadF(F0, F2_0); b.loadF(F1, F2_0)
    b.data.emitFeq(A0, F0, F1, FpS))
check "flt.s false", 0:
  (proc (b: var Buffer) =
    b.loadF(F0, F2_0); b.loadF(F1, F1_0)
    b.data.emitFlt(A0, F0, F1, FpS))
check "fle.s true on equal", 1:
  (proc (b: var Buffer) =
    b.loadF(F0, F2_0); b.loadF(F1, F2_0)
    b.data.emitFle(A0, F0, F1, FpS))
check "fcvt.w.s truncates toward zero", 2:
  (proc (b: var Buffer) =
    b.loadF(F0, 0x40266666'u32)       # 2.6f
    b.data.emitFcvtToInt(A0, F0, FpS, signed = true))
check "fcvt.w.s truncates a negative toward zero", 0xFFFFFFFE'u32:
  (proc (b: var Buffer) =
    b.loadF(F0, 0xC0266666'u32)       # -2.6f
    b.data.emitFcvtToInt(A0, F0, FpS, signed = true))
check "fcvt.s.w", F3_0:
  (proc (b: var Buffer) =
    b.data.emitLi(T0, 3)
    b.data.emitFcvtFromInt(F0, T0, FpS, signed = true)
    b.data.emitFmvXW(A0, F0))
check "fcvt.s.wu treats the operand as unsigned", 0x4F800000'u32:
  (proc (b: var Buffer) =
    b.data.emitLi(T0, 0xFFFFFFFF'u32)
    b.data.emitFcvtFromInt(F0, T0, FpS, signed = false)   # 4294967296.0f
    b.data.emitFmvXW(A0, F0))

# Doubles: `fld`/`fsd` and `.d` arithmetic, checked through memory because RV32
# has no `fmv.x.d`. 1.0 + 2.0 == 3.0, compared as the high word of the IEEE-754
# double 3.0 (0x40080000_00000000).
check "fadd.d through memory", 0x40080000'u32:
  (proc (b: var Buffer) =
    b.data.emitAddi(Sp, Sp, -32)
    b.data.emitLi(T0, 0); b.data.emitSw(T0, Sp, 0)
    b.data.emitLi(T0, 0x3FF00000'u32); b.data.emitSw(T0, Sp, 4)     # 1.0
    b.data.emitLi(T0, 0); b.data.emitSw(T0, Sp, 8)
    b.data.emitLi(T0, 0x40000000'u32); b.data.emitSw(T0, Sp, 12)    # 2.0
    b.data.emitFld(F0, Sp, 0)
    b.data.emitFld(F1, Sp, 8)
    b.data.emitFadd(F2, F0, F1, FpD)
    b.data.emitFsd(F2, Sp, 16)
    b.data.emitLw(A0, Sp, 20)                                       # high word
    b.data.emitAddi(Sp, Sp, 32))
check "fcvt.d.s widens exactly", 0x40080000'u32:
  (proc (b: var Buffer) =
    b.data.emitAddi(Sp, Sp, -16)
    b.loadF(F0, F3_0)                                               # 3.0f
    b.data.emitFcvtDS(F1, F0)
    b.data.emitFsd(F1, Sp, 0)
    b.data.emitLw(A0, Sp, 4)
    b.data.emitAddi(Sp, Sp, 16))
check "fcvt.s.d narrows", F3_0:
  (proc (b: var Buffer) =
    b.data.emitAddi(Sp, Sp, -16)
    b.data.emitLi(T0, 0); b.data.emitSw(T0, Sp, 0)
    b.data.emitLi(T0, 0x40080000'u32); b.data.emitSw(T0, Sp, 4)     # 3.0
    b.data.emitFld(F0, Sp, 0)
    b.data.emitFcvtSD(F1, F0)
    b.data.emitFmvXW(A0, F1)
    b.data.emitAddi(Sp, Sp, 16))
check "fcvt.w.d truncates", 7:
  (proc (b: var Buffer) =
    b.data.emitAddi(Sp, Sp, -16)
    b.data.emitLi(T0, 0); b.data.emitSw(T0, Sp, 0)
    b.data.emitLi(T0, 0x401E0000'u32); b.data.emitSw(T0, Sp, 4)     # 7.5
    b.data.emitFld(F0, Sp, 0)
    b.data.emitFcvtToInt(A0, F0, FpD, signed = true)
    b.data.emitAddi(Sp, Sp, 16))

# ── the image ───────────────────────────────────────────────────────────────

const
  LoadAddr = 0x8000_0000'u32
    ## QEMU's `virt` board puts RAM here and nothing below it, so a `-kernel`
    ## image is loaded and entered at this address. There is no separate flash
    ## region on this board; the real firmware layout (P3) takes both regions from
    ## the `(layout …)` file instead of from a constant.
  StackTop = LoadAddr + 0x0010_0000'u32
    ## 1 MiB above the image. Nothing else is in RAM, so this is simply "far
    ## enough away" — and unlike Cortex-M, no hardware reads it: a RISC-V core
    ## resets with `sp` undefined, so the entry code below sets it.

  # ARM semihosting's numbers, which RISC-V semihosting shares outright.
  SysExitExtended = 0x20
  AdpStoppedApplicationExit = 0x20026'u32

when isMainModule:
  # An optional check LIMIT as the second argument. A hang has no exit code to
  # report, so the only way to find which check is spinning is to build an image
  # that stops before it — which is a one-line facility and, without it, an
  # afternoon with a gdb stub.
  let limit = if paramCount() >= 2: parseInt(paramStr(2)) else: checks.len
  if limit < checks.len: checks.setLen limit

  var b = initBuffer()

  # The reset path. Two things a RISC-V core does NOT do for an image, both of
  # which hang rather than fault if skipped:
  #
  #  * it establishes no stack pointer — `sp` holds whatever reset left there;
  #  * it leaves the FPU off (`mstatus.FS = Off`), so the first floating-point
  #    instruction raises an illegal-instruction exception into an `mtvec` that
  #    has not been set either.
  b.data.emitLi(Sp, StackTop)
  b.data.emitEnableFpu()

  let lFail = b.createLabel()
  # `s1` (x9) is callee-saved, which is why the index lives there: the checks that
  # call `jal` clobber `ra` and every `t` register, and an index in one of those
  # would report the wrong check — or a garbage one — on failure.
  for i, c in checks:
    b.data.emitLi(S1, uint32(i + 1))
    c.emit(b)
    b.data.emitLi(T4, c.want)
    # `emitBranchFar`, not `emitBranch`: `lFail` is past every check, so by the
    # last few thousand bytes of image this is well beyond B-type's ±4 KiB. It is
    # also the only coverage the relaxed form gets, which is why the harness uses
    # it rather than being restructured to avoid needing it.
    b.emitBranchFar(Bne, A0, T4, lFail)

  b.data.emitLi(S1, 0)                # every check passed
  b.defineLabel(lFail)

  # exit(s1) via SYS_EXIT_EXTENDED. The two-word parameter block is built on the
  # stack, so the image needs no writable data section.
  b.data.emitAddi(Sp, Sp, -16)
  b.data.emitLi(T0, AdpStoppedApplicationExit)
  b.data.emitSw(T0, Sp, 0)
  b.data.emitSw(S1, Sp, 4)
  b.data.emitMv(A1, Sp)
  b.data.emitLi(A0, SysExitExtended)
  b.data.emitSemihostCall()
  # Semihosting exit does not return. If the host declines it, spin rather than
  # run off the end of the image into whatever RAM holds.
  block:
    let lSpin = b.createLabel()
    b.defineLabel(lSpin)
    b.emitJ(lSpin)

  b.absBase = LoadAddr
  b.updateRelocDisplacements()

  var code: seq[byte] = newSeq[byte](b.data.len)
  for i in 0 ..< b.data.len: code[i] = b.data[i]
  let image = writeElf32([Segment(vaddr: LoadAddr, data: code,
                                  memSize: code.len,
                                  flags: PF_R or PF_W or PF_X)],
                         LoadAddr, machine = EM_RISCV)
  writeFile(paramStr(1), image)
  echo "wrote ", paramStr(1), ": ", checks.len, " checks, ", code.len, " code bytes"
  for i, c in checks: echo "  ", i + 1, "  ", c.name
