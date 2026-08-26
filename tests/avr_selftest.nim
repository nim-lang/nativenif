## AVR encoder self-test: build ONE image that computes a list of expressions and
## compares each against its expected value, exiting with the 1-based index of
## the first mismatch (0 = every check passed).
##
## Running the instructions is the strongest oracle available. AVRtest's DECODER
## is the one that will execute whatever the backend emits, so "the result is
## right" checks the encoding at exactly the level that matters — and unlike a
## byte comparison it exercises the branch encoders and the relocation patcher
## too, which is where the AVR-specific hazard lives: flash is addressed in
## WORDS, so every displacement is halved on its way into an instruction.
##
## Each check leaves its 16-bit result in the pair r25:r24. The registers the
## harness itself uses — r17:r16 for the index, r19:r18 for the comparison — are
## therefore off limits to a check's operands.
##
##   nim c -o:bin/avr_selftest tests/avr_selftest.nim
##   bin/avr_selftest tests/avr_selftest.elf
##   bin/avrtest -q -mmcu=avr5 -s 32k tests/avr_selftest.elf ; echo $?

import std / [os, strutils]
import "../src/nifasm/avr/encoder"
import "../src/nifasm/core/buffers"
import "../src/nifasm/core/relocs"
import "../src/nifasm/image/elf32"

const
  RamEnd = 0x08FF     ## last SRAM byte on an ATmega328P-class part
  Scratch = 0x0400    ## well clear of the stack, for the load/store checks

type Check = object
  name: string
  emit: proc (b: var Buffer) {.closure.}   ## leave the computed value in r25:r24
  want: uint16

var checks: seq[Check] = @[]
proc check(name: string; want: uint16; emit: proc (b: var Buffer) {.closure.}) =
  checks.add Check(name: name, emit: emit, want: want)

proc ldw(b: var Buffer; pd: Pair; v: int) =
  ## A 16-bit constant into a pair: two `ldi`s, which is the only way there is.
  b.data.emitLdi(Register(ord(pd)), v and 0xFF)
  b.data.emitLdi(Register(ord(pd) + 1), (v shr 8) and 0xFF)

# ── moves and immediates ────────────────────────────────────────────────────

check "ldi pair", 0x1234:
  (proc (b: var Buffer) = b.ldw(P24, 0x1234))
check "movw copies a whole pair", 0xBEEF:
  (proc (b: var Buffer) =
    b.ldw(P18, 0xBEEF); b.data.emitMovw(P24, P18))
check "movw between low pairs", 0xCAFE:
  (proc (b: var Buffer) =
    b.ldw(P20, 0xCAFE)
    b.data.emitMovw(P2, P20)          # r3:r2 — no `ldi` reaches these
    b.data.emitMovw(P24, P2))
check "mov moves one half only", 0x00AB:
  (proc (b: var Buffer) =
    b.ldw(P20, 0x00AB); b.data.emitClr(R25); b.data.emitMov(R24, R20))
check "clr", 0:
  (proc (b: var Buffer) =
    b.ldw(P24, 0xFFFF); b.data.emitClr(R24); b.data.emitClr(R25))
check "ser is ldi 0xFF", 0xFFFF:
  (proc (b: var Buffer) =
    b.data.emitSer(R24); b.data.emitSer(R25))

# ── 16-bit arithmetic, built from 8-bit parts ───────────────────────────────
# The carry between the halves is the whole point of these.

check "add+adc carries into the high half", 0x0100:
  (proc (b: var Buffer) =
    b.ldw(P24, 0x00FF); b.ldw(P18, 0x0001)
    b.data.emitAdd(R24, R18); b.data.emitAdc(R25, R19))
check "add+adc without a carry", 0x3579:
  (proc (b: var Buffer) =
    b.ldw(P24, 0x1234); b.ldw(P18, 0x2345)
    b.data.emitAdd(R24, R18); b.data.emitAdc(R25, R19))
check "sub+sbc borrows from the high half", 0x00FF:
  (proc (b: var Buffer) =
    b.ldw(P24, 0x0100); b.ldw(P18, 0x0001)
    b.data.emitSub(R24, R18); b.data.emitSbc(R25, R19))
check "subi+sbci", 0x0FFF:
  (proc (b: var Buffer) =
    b.ldw(P24, 0x1000)
    b.data.emitSubi(R24, 0x01); b.data.emitSbci(R25, 0x00))
check "subi+sbci ADDS by subtracting the negation", 0x1010:
  (proc (b: var Buffer) =
    b.ldw(P24, 0x1000)
    b.data.emitSubi(R24, 0xF0)      # -16
    b.data.emitSbci(R25, 0xFF))
check "adiw", 0x0110:
  (proc (b: var Buffer) = b.ldw(P24, 0x00F0); b.data.emitAdiw(P24, 32))
check "adiw carries", 0x0100:
  (proc (b: var Buffer) = b.ldw(P24, 0x00FF); b.data.emitAdiw(P24, 1))
check "sbiw", 0x00F0:
  (proc (b: var Buffer) = b.ldw(P24, 0x0110); b.data.emitSbiw(P24, 32))
check "sbiw borrows", 0x00FF:
  (proc (b: var Buffer) = b.ldw(P24, 0x0100); b.data.emitSbiw(P24, 1))
check "com/neg/sbci negates a pair", 0xFFFF:
  (proc (b: var Buffer) =
    b.ldw(P24, 0x0001)
    b.data.emitCom(R25); b.data.emitNeg(R24); b.data.emitSbci(R25, 0xFF))
check "negating 0x1234", 0xEDCC:
  (proc (b: var Buffer) =
    b.ldw(P24, 0x1234)
    b.data.emitCom(R25); b.data.emitNeg(R24); b.data.emitSbci(R25, 0xFF))
check "inc/dec", 0x1234:
  (proc (b: var Buffer) =
    b.ldw(P24, 0x1234); b.data.emitInc(R24); b.data.emitDec(R24))

# ── logic ───────────────────────────────────────────────────────────────────

check "and", 0x1200:
  (proc (b: var Buffer) =
    b.ldw(P24, 0x1234); b.ldw(P18, 0xFF00)
    b.data.emitAnd(R24, R18); b.data.emitAnd(R25, R19))
check "or", 0xFF34:
  (proc (b: var Buffer) =
    b.ldw(P24, 0x1234); b.ldw(P18, 0xFF00)
    b.data.emitOr(R24, R18); b.data.emitOr(R25, R19))
check "eor", 0xED34:
  (proc (b: var Buffer) =
    b.ldw(P24, 0x1234); b.ldw(P18, 0xFF00)
    b.data.emitEor(R24, R18); b.data.emitEor(R25, R19))
check "andi", 0x0034:
  (proc (b: var Buffer) =
    b.ldw(P24, 0x1234); b.data.emitAndi(R24, 0xFF); b.data.emitAndi(R25, 0x00))
check "ori", 0x12FF:
  (proc (b: var Buffer) =
    b.ldw(P24, 0x1200); b.data.emitOri(R24, 0xFF))
check "swap exchanges the nibbles", 0x1243:
  (proc (b: var Buffer) = b.ldw(P24, 0x1234); b.data.emitSwap(R24))

# ── shifts, one bit at a time ───────────────────────────────────────────────

check "lsl+rol shifts a pair left", 0x2468:
  (proc (b: var Buffer) =
    b.ldw(P24, 0x1234); b.data.emitLsl(R24); b.data.emitRol(R25))
check "lsl+rol carries across the halves", 0x0100:
  (proc (b: var Buffer) =
    b.ldw(P24, 0x0080); b.data.emitLsl(R24); b.data.emitRol(R25))
check "lsr+ror shifts a pair right, unsigned", 0x091A:
  (proc (b: var Buffer) =
    b.ldw(P24, 0x1234); b.data.emitLsr(R25); b.data.emitRor(R24))
check "asr+ror keeps the sign", 0xC080:
  (proc (b: var Buffer) =
    b.ldw(P24, 0x8100); b.data.emitAsr(R25); b.data.emitRor(R24))
check "shift left by four is four pairs", 0x2340:
  (proc (b: var Buffer) =
    b.ldw(P24, 0x1234)
    for _ in 0 ..< 4: (b.data.emitLsl(R24); b.data.emitRol(R25)))

# ── multiply ────────────────────────────────────────────────────────────────

check "mul lands in r1:r0", 600:
  (proc (b: var Buffer) =
    b.data.emitLdi(R18, 200); b.data.emitLdi(R20, 3)
    b.data.emitMul(R18, R20)
    b.data.emitMovw(P24, P0)
    b.data.emitClr(R1))                    # restore the zero register
check "mul overflowing one byte", 0xFE01:
  (proc (b: var Buffer) =
    b.data.emitLdi(R18, 255); b.data.emitLdi(R20, 255)
    b.data.emitMul(R18, R20)
    b.data.emitMovw(P24, P0)
    b.data.emitClr(R1))
check "muls is signed", 0xFFF6:                # -10 == -5 * 2
  (proc (b: var Buffer) =
    b.data.emitLdi(R18, 0xFB); b.data.emitLdi(R20, 2)   # -5, 2
    b.data.emitMuls(R18, R20)
    b.data.emitMovw(P24, P0)
    b.data.emitClr(R1))

# ── memory ──────────────────────────────────────────────────────────────────

check "st/ld through Z", 0xDEAD:
  (proc (b: var Buffer) =
    b.ldw(Z, Scratch); b.ldw(P18, 0xDEAD)
    b.data.emitSt(PZ, R18); b.data.emitStd(PZ, 1, R19)
    b.data.emitClr(R24); b.data.emitClr(R25)
    b.data.emitLd(R24, PZ); b.data.emitLdd(R25, PZ, 1))
check "st/ld through X (no displaced form)", 0x005A:
  (proc (b: var Buffer) =
    b.ldw(X, Scratch + 0x10); b.data.emitLdi(R18, 0x5A)
    b.data.emitSt(PX, R18)
    b.data.emitClr(R24); b.data.emitClr(R25)
    b.data.emitLd(R24, PX))
check "std/ldd through Y at a displacement", 0x4321:
  (proc (b: var Buffer) =
    b.ldw(Y, Scratch + 0x20); b.ldw(P18, 0x4321)
    b.data.emitStd(PY, 6, R18); b.data.emitStd(PY, 7, R19)
    b.data.emitClr(R24); b.data.emitClr(R25)
    b.data.emitLdd(R24, PY, 6); b.data.emitLdd(R25, PY, 7))
check "std/ldd at the top of the displacement range", 0x9876:
  (proc (b: var Buffer) =
    b.ldw(Z, Scratch + 0x30); b.ldw(P18, 0x9876)
    b.data.emitStd(PZ, 62, R18); b.data.emitStd(PZ, 63, R19)
    b.data.emitClr(R24); b.data.emitClr(R25)
    b.data.emitLdd(R24, PZ, 62); b.data.emitLdd(R25, PZ, 63))
check "sts/lds direct", 0xBABE:
  (proc (b: var Buffer) =
    b.ldw(P18, 0xBABE)
    b.data.emitSts(Scratch + 0x80, R18); b.data.emitSts(Scratch + 0x81, R19)
    b.data.emitClr(R24); b.data.emitClr(R25)
    b.data.emitLds(R24, Scratch + 0x80); b.data.emitLds(R25, Scratch + 0x81))
check "post-increment walks a buffer", 0x0201:
  (proc (b: var Buffer) =
    b.ldw(X, Scratch + 0x90)
    b.data.emitLdi(R18, 1); b.data.emitStInc(PX, R18)
    b.data.emitLdi(R18, 2); b.data.emitStInc(PX, R18)
    b.ldw(X, Scratch + 0x90)
    b.data.emitLdInc(R24, PX); b.data.emitLdInc(R25, PX))
check "push/pop round-trips a pair", 0xFACE:
  (proc (b: var Buffer) =
    b.ldw(P18, 0xFACE)
    b.data.emitPush(R18); b.data.emitPush(R19)
    b.data.emitClr(R18); b.data.emitClr(R19)
    b.data.emitPop(R25); b.data.emitPop(R24))
check "in/out reach the I/O space", 0x08FF:
  (proc (b: var Buffer) =
    b.data.emitIn(R24, SplIo); b.data.emitIn(R25, SphIo))

# ── comparison ──────────────────────────────────────────────────────────────
# `cp`+`cpc` is how a 16-bit comparison is done, and the flags it leaves are
# what every branch below reads.

check "cp+cpc finds equality", 1:
  (proc (b: var Buffer) =
    let lNe = b.createLabel()
    b.ldw(P20, 0x1234); b.ldw(P18, 0x1234)
    b.data.emitCp(R20, R18); b.data.emitCpc(R21, R19)
    b.ldw(P24, 1)
    b.emitBranch(CondEq, lNe)
    b.ldw(P24, 0)
    b.defineLabel(lNe))
check "cp+cpc finds inequality in the HIGH half", 0:
  (proc (b: var Buffer) =
    let lNe = b.createLabel()
    b.ldw(P20, 0x1234); b.ldw(P18, 0x9234)
    b.data.emitCp(R20, R18); b.data.emitCpc(R21, R19)
    b.ldw(P24, 1)
    b.emitBranch(CondEq, lNe)
    b.ldw(P24, 0)
    b.defineLabel(lNe))
check "cpi", 1:
  (proc (b: var Buffer) =
    let lEq = b.createLabel()
    b.data.emitLdi(R20, 42); b.data.emitCpi(R20, 42)
    b.ldw(P24, 1)
    b.emitBranch(CondEq, lEq)
    b.ldw(P24, 0)
    b.defineLabel(lEq))
check "unsigned less-than lands in the carry", 1:
  (proc (b: var Buffer) =
    let lLo = b.createLabel()
    b.ldw(P20, 0x0FFF); b.ldw(P18, 0x1000)
    b.data.emitCp(R20, R18); b.data.emitCpc(R21, R19)
    b.ldw(P24, 1)
    b.emitBranch(CondLo, lLo)
    b.ldw(P24, 0)
    b.defineLabel(lLo))
check "signed less-than needs CondLt, not CondLo", 1:
  (proc (b: var Buffer) =
    let lLt = b.createLabel()
    b.ldw(P20, 0xFFFF); b.ldw(P18, 0x0001)      # -1 < 1
    b.data.emitCp(R20, R18); b.data.emitCpc(R21, R19)
    b.ldw(P24, 1)
    b.emitBranch(CondLt, lLt)
    b.ldw(P24, 0)
    b.defineLabel(lLt))
check "and CondLo gets that one WRONG, as unsigned", 0:
  (proc (b: var Buffer) =
    let lLo = b.createLabel()
    b.ldw(P20, 0xFFFF); b.ldw(P18, 0x0001)      # 65535 > 1, unsigned
    b.data.emitCp(R20, R18); b.data.emitCpc(R21, R19)
    b.ldw(P24, 1)
    b.emitBranch(CondLo, lLo)
    b.ldw(P24, 0)
    b.defineLabel(lLo))
check "tst sets Z", 1:
  (proc (b: var Buffer) =
    let lZ = b.createLabel()
    b.data.emitClr(R20); b.data.emitTst(R20)
    b.ldw(P24, 1)
    b.emitBranch(CondEq, lZ)
    b.ldw(P24, 0)
    b.defineLabel(lZ))
check "cpse skips exactly one instruction", 7:
  (proc (b: var Buffer) =
    b.data.emitLdi(R20, 5); b.data.emitLdi(R21, 5)
    b.ldw(P24, 7)
    b.data.emitCpse(R20, R21)
    b.ldw(P24, 9))                              # skipped: only the low `ldi`...
check "...and cpse skips ONE WORD, not one statement", 0x0007:
  (proc (b: var Buffer) =
    b.data.emitLdi(R20, 5); b.data.emitLdi(R21, 5)
    b.ldw(P24, 0x0707)
    b.data.emitCpse(R20, R21)
    b.ldw(P24, 0x0009))
    # Only the LOW `ldi` is skipped, so r24 keeps 0x07 while r25 is still
    # overwritten with 0x00 — 0x0007, not the 0x0707 that "skip the assignment"
    # would give. Loading a 16-bit constant is two instructions here, and a skip
    # counts instructions.
check "sbrc skips when the bit is clear", 3:
  (proc (b: var Buffer) =
    b.data.emitLdi(R20, 0b1111_1110)
    b.ldw(P24, 3)
    b.data.emitSbrc(R20, 0)
    b.data.emitLdi(R24, 4))
check "sbrs skips when the bit is set", 3:
  (proc (b: var Buffer) =
    b.data.emitLdi(R20, 0b0000_0001)
    b.ldw(P24, 3)
    b.data.emitSbrs(R20, 0)
    b.data.emitLdi(R24, 4))

# ── control flow and relocation ─────────────────────────────────────────────

check "rjmp forward", 5:
  (proc (b: var Buffer) =
    let l = b.createLabel()
    b.ldw(P24, 5)
    b.emitRjmp(l)
    b.ldw(P24, 6)
    b.defineLabel(l))
check "jmp forward (two words, absolute)", 5:
  (proc (b: var Buffer) =
    let l = b.createLabel()
    b.ldw(P24, 5)
    b.emitJmp(l)
    b.ldw(P24, 6)
    b.defineLabel(l))
check "a backward branch closes a counted loop", 30:
  (proc (b: var Buffer) =
    let top = b.createLabel()
    b.data.emitLdi(R18, 10)
    b.ldw(P24, 0)
    b.defineLabel(top)
    b.data.emitAdiw(P24, 3)
    b.data.emitSubi(R18, 1)
    b.emitBranch(CondNe, top))
check "a loop whose body outgrows the branch's reach", 300:
  (proc (b: var Buffer) =
    # ±128 bytes is the whole reach of a conditional branch, so a body this size
    # can only be closed by inverting the condition and branching over an
    # `rjmp` — which is what the selector will have to do for real.
    let top = b.createLabel()
    let outʹ = b.createLabel()
    b.data.emitLdi(R18, 100)
    b.ldw(P24, 0)
    b.defineLabel(top)
    b.data.emitAdiw(P24, 3)
    for _ in 0 ..< 60: b.data.emitNop()      # 120 bytes of body
    b.data.emitSubi(R18, 1)
    b.emitBranch(CondEq, outʹ)
    b.emitRjmp(top)
    b.defineLabel(outʹ))
check "rcall and ret", 0x0007:
  (proc (b: var Buffer) =
    let sub = b.createLabel()
    let after = b.createLabel()
    b.emitRcall(sub)
    b.emitRjmp(after)
    b.defineLabel(sub)
    b.ldw(P24, 10); b.ldw(P18, 3)
    b.data.emitSub(R24, R18); b.data.emitSbc(R25, R19)
    b.data.emitRet()
    b.defineLabel(after))
check "call and ret (two words, absolute)", 0x0007:
  (proc (b: var Buffer) =
    let sub = b.createLabel()
    let after = b.createLabel()
    b.emitCall(sub)
    b.emitRjmp(after)
    b.defineLabel(sub)
    b.ldw(P24, 10); b.ldw(P18, 3)
    b.data.emitSub(R24, R18); b.data.emitSbc(R25, R19)
    b.data.emitRet()
    b.defineLabel(after))
check "icall through Z, the only indirect call", 0x0042:
  (proc (b: var Buffer) =
    let sub = b.createLabel()
    let after = b.createLabel()
    # Z takes the WORD address of the target, since that is what the PC counts.
    b.emitLdiAddr(Z, sub)
    b.data.emitLsr(R31); b.data.emitRor(R30)   # byte address -> word address
    b.data.emitIcall()
    b.emitRjmp(after)
    b.defineLabel(sub)
    b.ldw(P24, 0x42)
    b.data.emitRet()
    b.defineLabel(after))
check "ldiAddr materializes a label's address", 1:
  (proc (b: var Buffer) =
    # Not the value — the image's load address is 0 here, so the byte address of
    # a label a few hundred bytes in is whatever it is. What is checked is that
    # the two halves agree with each other and with a nonzero address.
    let l = b.createLabel()
    let ok = b.createLabel()
    b.emitLdiAddr(P18, l)
    b.ldw(P24, 1)
    b.data.emitOr(R18, R19)
    b.emitBranch(CondNe, ok)
    b.ldw(P24, 0)
    b.defineLabel(ok)
    b.defineLabel(l))

when isMainModule:
  if paramCount() >= 1 and paramStr(1) == "--list":
    for i, c in checks: echo i + 1, "\t", c.name
    quit 0

  # `--mutate:N` corrupts check N's EXPECTED value BEFORE the image is built, so
  # a run must then fail with exactly N. Without it a check that silently
  # computes nothing — an emitter that writes no bytes, a comparison against a
  # value the harness itself happened to leave in the pair — passes and says so.
  # `tests/tester` sweeps all of them.
  if paramCount() >= 2 and paramStr(2).startsWith("--mutate:"):
    let m = parseInt(paramStr(2)[9 .. ^1])
    if m < 1 or m > checks.len:
      quit "avr_selftest: --mutate: out of range 1.." & $checks.len
    checks[m - 1].want = checks[m - 1].want xor 0x5A5A'u16

  var b = initBuffer()
  let lDone = b.createLabel()

  # ── reset ──
  # SP is an I/O register pair, not a GPR, so it is established with `out`; and
  # r1 must hold zero, which is the convention every `sbc`-style sequence and
  # `mul` fixup here relies on.
  b.data.emitLdi(R16, RamEnd and 0xFF)
  b.data.emitOut(SplIo, R16)
  b.data.emitLdi(R16, RamEnd shr 8)
  b.data.emitOut(SphIo, R16)
  b.data.emitClr(R1)

  for i, c in checks:
    # r17:r16 carries the 1-based index, so the failure path reports WHICH check
    # broke with no per-check code.
    b.ldw(P16, i + 1)
    c.emit(b)
    b.ldw(P18, int(c.want))
    b.data.emitCp(R24, R18)
    b.data.emitCpc(R25, R19)
    let pass = b.createLabel()
    b.emitBranch(CondEq, pass)
    b.emitJmp(lDone)          # absolute: the image outgrows every relative reach
    b.defineLabel(pass)

  b.ldw(P16, 0)               # every check passed
  b.defineLabel(lDone)
  b.data.emitMovw(P24, P16)   # exit(r25:r24)
  b.data.emitCpse(R30, R30)   # AVRtest SYSCALL 30, and the invalid opcode it
  b.data.addUint16 0xFFFF     # always skips
  let spin = b.createLabel()  # unreachable; `rjmp .` if the simulator returns
  b.defineLabel(spin)
  b.emitRjmp(spin)

  finalize(b)

  var code = newSeq[byte](b.data.len)
  for i in 0 ..< b.data.len: code[i] = b.data[i]

  let outFile = if paramCount() >= 1: paramStr(1) else: "avr_selftest.elf"
  let img = writeElf32(
    [Segment(vaddr: 0, data: code, memSize: code.len, flags: PF_R or PF_X)],
    entry = 0, machine = EM_AVR, flags = EF_AVR_MACH_AVR5, entryTag = 0)
  writeFile(outFile, img)
  echo outFile, ": ", code.len, " bytes, ", checks.len, " checks"
