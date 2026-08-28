#
#           nativenif — AVR target probe (milestone M0)
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## Hand-builds an AVR ELF32 image that exercises every host facility the AVR
## backend's TEST STRATEGY depends on, and nothing else. It predates the backend
## on purpose: if this stops working, the failure is in the target contract
## (AVRtest, the syscall ABI, the ELF shape), not in the code generator — which
## is exactly the distinction that is impossible to make once a several-thousand
## line backend sits in between. `tools/cortexm_probe.nim` is the same tool for
## the same reason.
##
## What it proves:
##   * an AVR ELF32 (`EM_AVR`, one PT_LOAD at flash address 0) loads and runs
##   * the AVRtest syscall ABI: the pseudo-instruction `SYSCALL N` is
##     `CPSE rN, rN` followed by the invalid opcode `0xFFFF`, i.e. "always skip
##     the thing that would trap". Syscall 29 is `putchar(r24)` and syscall 30 is
##     `exit(r25:r24)`
##   * that AVRtest forwards that status as its own process exit status, which is
##     what lets `.exitcode` fixtures work the way they do on every other target
##   * the encodings the backend's 16-bit register pairs are BUILT from, each
##     checked by computing with it: `ldi`/`movw`, `add`+`adc` and `sub`+`sbc`
##     across the halves, `subi`/`sbci`, `adiw`/`sbiw`, the `com`/`neg`/`sbci`
##     negation, `lsl`+`rol` and `asr`+`ror`, `mul`, all three pointer registers
##     (X, Y+q, Z+q), `sts`/`lds`, `push`/`pop`, `rcall`/`call`/`ret`, and a
##     `brne` loop closing backwards
##
## The image self-checks: every check exits with its own 1-based index on
## mismatch, so a failure NAMES the broken encoding instead of just producing a
## wrong answer. Exit code 0 from a `-q` run means every check passed and the
## requested status was reached.
##
## Build & run:
##   nim c -o:bin/avr_probe tools/avr_probe.nim
##   bin/avr_probe /tmp/probe.elf 42
##   bin/avrtest -q -mmcu=avr5 -s 32k /tmp/probe.elf ; echo $?

import std / [os, strutils]

type Img = object
  w: seq[uint16]   ## flash is addressed in 16-bit words, so that is the unit

proc put(i: var Img; v: int) = i.w.add uint16(v and 0xFFFF)
proc at(i: Img): int = i.w.len   ## the next WORD address

# ── AVR encodings ───────────────────────────────────────────────────────────
# Hand-rolled here rather than imported: this tool must stay independent of the
# backend, so it can arbitrate whether a failure is ours or the host's.
#
# Two operand restrictions run through all of this and shape the register model
# the backend is built on, so they are asserted rather than commented:
# `ldi`/`subi`/`sbci`/`cpi` reach only r16..r31, and `adiw`/`sbiw` only the four
# upper pairs r25:r24, X, Y and Z.

proc ldi(i: var Img; d, k: int) =
  ## `1110 KKKK dddd KKKK` — the only way to get a constant into a register, and
  ## it does not reach r0..r15. A constant destined for a low register goes via
  ## a high one and `mov`/`movw`.
  assert d in 16..31
  i.put 0xE000 or (((k shr 4) and 0xF) shl 8) or ((d - 16) shl 4) or (k and 0xF)

proc mov(i: var Img; d, r: int) =
  i.put 0x2C00 or ((r and 0x10) shl 5) or ((d and 0x1F) shl 4) or (r and 0xF)

proc movw(i: var Img; d, r: int) =
  ## `0000 0001 dddd rrrr` — copies a whole even-aligned PAIR in one instruction.
  ## This is what makes "a pair is one logical register" cheap rather than a
  ## two-instruction fiction.
  assert d mod 2 == 0 and r mod 2 == 0
  i.put 0x0100 or ((d shr 1) shl 4) or (r shr 1)

proc add(i: var Img; d, r: int) =
  i.put 0x0C00 or ((r and 0x10) shl 5) or ((d and 0x1F) shl 4) or (r and 0xF)
proc adc(i: var Img; d, r: int) =
  i.put 0x1C00 or ((r and 0x10) shl 5) or ((d and 0x1F) shl 4) or (r and 0xF)
proc sub(i: var Img; d, r: int) =
  i.put 0x1800 or ((r and 0x10) shl 5) or ((d and 0x1F) shl 4) or (r and 0xF)
proc sbc(i: var Img; d, r: int) =
  i.put 0x0800 or ((r and 0x10) shl 5) or ((d and 0x1F) shl 4) or (r and 0xF)
proc eor(i: var Img; d, r: int) =
  i.put 0x2400 or ((r and 0x10) shl 5) or ((d and 0x1F) shl 4) or (r and 0xF)
proc cp(i: var Img; d, r: int) =
  i.put 0x1400 or ((r and 0x10) shl 5) or ((d and 0x1F) shl 4) or (r and 0xF)
proc cpc(i: var Img; d, r: int) =
  i.put 0x0400 or ((r and 0x10) shl 5) or ((d and 0x1F) shl 4) or (r and 0xF)
proc mul(i: var Img; d, r: int) =
  ## 8x8 -> 16, and the product lands in the FIXED pair r1:r0 — the one reason
  ## r1:r0 cannot be an allocatable pair.
  i.put 0x9C00 or ((r and 0x10) shl 5) or ((d and 0x1F) shl 4) or (r and 0xF)

proc subi(i: var Img; d, k: int) =
  assert d in 16..31
  i.put 0x5000 or (((k shr 4) and 0xF) shl 8) or ((d - 16) shl 4) or (k and 0xF)
proc sbci(i: var Img; d, k: int) =
  assert d in 16..31
  i.put 0x4000 or (((k shr 4) and 0xF) shl 8) or ((d - 16) shl 4) or (k and 0xF)

proc adiw(i: var Img; d, k: int) =
  ## `1001 0110 KKdd KKKK` — a 6-bit immediate added to a PAIR in one
  ## instruction, on r25:r24, X, Y and Z only.
  assert d in [24, 26, 28, 30] and k in 0..63
  i.put 0x9600 or ((k and 0x30) shl 2) or (((d - 24) shr 1) shl 4) or (k and 0xF)
proc sbiw(i: var Img; d, k: int) =
  assert d in [24, 26, 28, 30] and k in 0..63
  i.put 0x9700 or ((k and 0x30) shl 2) or (((d - 24) shr 1) shl 4) or (k and 0xF)

proc outIo(i: var Img; a, r: int) =
  ## The I/O address space, reached only by `in`/`out`. SPL/SPH live at 0x3D/0x3E
  ## there, which is how the reset code sets up a stack.
  assert a in 0..63
  i.put 0xB800 or ((a and 0x30) shl 5) or ((r and 0x1F) shl 4) or (a and 0xF)

proc sts(i: var Img; k, r: int) =
  ## 32-bit direct store. Two words, so a global access costs twice what an
  ## indirect one does — but it needs no pointer register, of which there are
  ## exactly three.
  i.put 0x9200 or ((r and 0x1F) shl 4); i.put k
proc lds(i: var Img; d, k: int) =
  i.put 0x9000 or ((d and 0x1F) shl 4); i.put k

proc stZ(i: var Img; r: int) = i.put 0x8200 or ((r and 0x1F) shl 4)
proc ldZ(i: var Img; d: int) = i.put 0x8000 or ((d and 0x1F) shl 4)
proc stX(i: var Img; r: int) = i.put 0x920C or ((r and 0x1F) shl 4)
proc ldX(i: var Img; d: int) = i.put 0x900C or ((d and 0x1F) shl 4)

proc stdZ(i: var Img; q, r: int) =
  ## `st Z+q` — displacement 0..63, and only off Y or Z. X has no displaced form
  ## at all, which is why Y is the frame pointer and Z the addressing bridge.
  assert q in 0..63
  i.put 0x8200 or ((q and 0x20) shl 8) or ((q and 0x18) shl 7) or
       ((r and 0x1F) shl 4) or (q and 7)
proc lddZ(i: var Img; d, q: int) =
  assert q in 0..63
  i.put 0x8000 or ((q and 0x20) shl 8) or ((q and 0x18) shl 7) or
       ((d and 0x1F) shl 4) or (q and 7)
proc stdY(i: var Img; q, r: int) =
  assert q in 0..63
  i.put 0x8208 or ((q and 0x20) shl 8) or ((q and 0x18) shl 7) or
       ((r and 0x1F) shl 4) or (q and 7)
proc lddY(i: var Img; d, q: int) =
  assert q in 0..63
  i.put 0x8008 or ((q and 0x20) shl 8) or ((q and 0x18) shl 7) or
       ((d and 0x1F) shl 4) or (q and 7)

proc push(i: var Img; r: int) = i.put 0x920F or ((r and 0x1F) shl 4)
proc pop(i: var Img; d: int) = i.put 0x900F or ((d and 0x1F) shl 4)

proc com(i: var Img; d: int) = i.put 0x9400 or ((d and 0x1F) shl 4)
proc neg(i: var Img; d: int) = i.put 0x9401 or ((d and 0x1F) shl 4)
proc asr(i: var Img; d: int) = i.put 0x9405 or ((d and 0x1F) shl 4)
proc ror(i: var Img; d: int) = i.put 0x9407 or ((d and 0x1F) shl 4)

proc lsl(i: var Img; d: int) = i.add(d, d)   ## `lsl` IS `add rd, rd`
proc rol(i: var Img; d: int) = i.adc(d, d)   ## and `rol` IS `adc rd, rd`
proc clr(i: var Img; d: int) = i.eor(d, d)   ## and `clr` IS `eor rd, rd`

proc rcall(i: var Img; k: int) = i.put 0xD000 or (k and 0xFFF)
proc brne(i: var Img; k: int) = i.put 0xF401 or ((k and 0x7F) shl 3)
proc breq(i: var Img; k: int) = i.put 0xF001 or ((k and 0x7F) shl 3)
proc ret(i: var Img) = i.put 0x9508

proc callWords(k: int): (int, int) =
  ## 32-bit `call`, whose 22-bit WORD address is scattered across both halves.
  (0x940E or (((k shr 17) and 0x1F) shl 4) or ((k shr 16) and 1), k and 0xFFFF)

proc call(i: var Img; k: int) =
  let (a, b) = callWords(k); i.put a; i.put b

proc syscall(i: var Img; n: int) =
  ## AVRtest's pseudo-instruction: `CPSE rN, rN` — which always skips — followed
  ## by the invalid opcode 0xFFFF it therefore never executes. The simulator
  ## recognises the pair; real silicon would simply skip and carry on.
  i.put 0x1000 or ((n and 0x1F) shl 4) or (n and 0xF) or ((n and 0x10) shl 5)
  i.put 0xFFFF

const
  SysPutchar = 29   ## r24 = the character
  SysExit = 30      ## r25:r24 = the status

# ── image layout ────────────────────────────────────────────────────────────

const
  RamEnd = 0x08FF
    ## Last SRAM byte on an ATmega328P-class part. The stack starts here and
    ## grows down; nothing in the probe comes near the bottom.
  ScratchRam = 0x0200
    ## Well above the stack's reach, for the load/store checks.
  CheckLo = 16
  CheckHi = 17
    ## r17:r16 is the comparison temp. Held out of every check's operands so a
    ## check cannot corrupt the thing it is checking with.

proc buildImage(exitCode: int): (seq[byte], int) =
  var i = Img()
  var checks = 0

  proc puts(i: var Img; s: string) =
    for c in s:
      i.ldi 24, ord(c)
      i.syscall SysPutchar

  proc check16(i: var Img; lo, exp: int) =
    ## Compare the pair `lo+1:lo` against `exp` and exit with this check's
    ## 1-based index if they differ. Four words of fail block, which is what the
    ## `breq` skips.
    inc checks
    i.ldi CheckLo, exp and 0xFF
    i.ldi CheckHi, (exp shr 8) and 0xFF
    i.cp lo, CheckLo
    i.cpc lo + 1, CheckHi
    i.breq 4
    i.ldi 24, checks
    i.ldi 25, 0
    i.syscall SysExit

  # ── reset: a stack, and r1 zeroed ─────────────────────────────────────────
  # SP is an I/O register pair, not a GPR, so it is written through `out`.
  i.ldi 28, RamEnd and 0xFF
  i.outIo 0x3D, 28
  i.ldi 28, RamEnd shr 8
  i.outIo 0x3E, 28
  i.clr 1

  i.puts "AVR probe\n"

  # 1. `ldi` a 16-bit constant into a pair, then copy the pair with one `movw`.
  i.ldi 18, 0x34
  i.ldi 19, 0x12
  i.movw 20, 18
  i.check16 20, 0x1234

  # 2. A 16-bit add is `add`+`adc`: the carry out of the low half is the whole
  #    reason the two halves cannot be emitted independently.
  i.ldi 18, 0xFF
  i.ldi 19, 0x00
  i.ldi 20, 0x01
  i.ldi 21, 0x00
  i.add 18, 20
  i.adc 19, 21
  i.check16 18, 0x0100

  # 3. And a 16-bit subtract is `sub`+`sbc`, borrowing the same way.
  i.ldi 18, 0x00
  i.ldi 19, 0x01
  i.ldi 20, 0x01
  i.ldi 21, 0x00
  i.sub 18, 20
  i.sbc 19, 21
  i.check16 18, 0x00FF

  # 4. `subi`/`sbci` — the immediate forms. There is no `addi`: adding a
  #    constant means subtracting its negation.
  i.ldi 18, 0x00
  i.ldi 19, 0x10
  i.subi 18, 0x01
  i.sbci 19, 0x00
  i.check16 18, 0x0FFF

  # 5. `adiw`/`sbiw` do reach a pair directly, on four pairs and up to 63.
  i.ldi 24, 0xF0
  i.ldi 25, 0x00
  i.adiw 24, 0x20
  i.check16 24, 0x0110
  i.sbiw 24, 0x10
  i.check16 24, 0x0100

  # 6. Negating a pair: complement the high half, negate the low, then borrow.
  i.ldi 18, 0x01
  i.ldi 19, 0x00
  i.com 19
  i.neg 18
  i.sbci 19, 0xFF
  i.check16 18, 0xFFFF

  # 7/8. Shifts move ONE bit and carry between the halves, so a shift by a
  #      constant is that many instruction pairs and a variable shift is a loop.
  i.ldi 18, 0x80
  i.ldi 19, 0x00
  i.lsl 18
  i.rol 19
  i.check16 18, 0x0100

  i.ldi 18, 0x00
  i.ldi 19, 0x81
  i.asr 19
  i.ror 18
  i.check16 18, 0xC080

  # 9. `mul` writes r1:r0, and r1 must be zeroed again afterwards.
  i.ldi 18, 200
  i.ldi 20, 3
  i.mul 18, 20
  i.movw 22, 0
  i.clr 1
  i.check16 22, 600

  # 10. SRAM through Z, plain and displaced.
  i.ldi 30, ScratchRam and 0xFF
  i.ldi 31, ScratchRam shr 8
  i.ldi 18, 0xAD
  i.ldi 19, 0xDE
  i.stZ 18
  i.stdZ 1, 19
  i.clr 20
  i.clr 21
  i.ldZ 20
  i.lddZ 21, 1
  i.check16 20, 0xDEAD

  # 11. Through X, which has no displaced form; then the direct 32-bit forms.
  i.ldi 26, (ScratchRam + 0x10) and 0xFF
  i.ldi 27, (ScratchRam + 0x10) shr 8
  i.ldi 18, 0x5A
  i.stX 18
  i.clr 20
  i.ldX 20
  i.clr 21
  i.check16 20, 0x005A

  i.ldi 18, 0xBE
  i.ldi 19, 0xBA
  i.sts ScratchRam + 0x20, 18
  i.sts ScratchRam + 0x21, 19
  i.clr 20
  i.clr 21
  i.lds 20, ScratchRam + 0x20
  i.lds 21, ScratchRam + 0x21
  i.check16 20, 0xBABE

  # 12. Y+displacement — the frame-slot addressing mode the backend will live on.
  i.ldi 28, (ScratchRam + 0x100) and 0xFF
  i.ldi 29, (ScratchRam + 0x100) shr 8
  i.ldi 18, 0x21
  i.ldi 19, 0x43
  i.stdY 6, 18
  i.stdY 7, 19
  i.clr 20
  i.clr 21
  i.lddY 20, 6
  i.lddY 21, 7
  i.check16 20, 0x4321

  # 13. push/pop. Y doubled as a scratch pointer just above, so the stack
  #     pointer is re-established first — SP lives in I/O space, not in Y.
  i.ldi 28, RamEnd and 0xFF
  i.outIo 0x3D, 28
  i.ldi 28, RamEnd shr 8
  i.outIo 0x3E, 28
  i.ldi 18, 0xCE
  i.ldi 19, 0xFA
  i.push 18
  i.push 19
  i.clr 18
  i.clr 19
  i.pop 19
  i.pop 18
  i.check16 18, 0xFACE

  # 14. A real call and return, reached both ways: `rcall` is one word and
  #     PC-relative, `call` is two and absolute.
  let rcallSite = i.at
  i.rcall 0                     # patched once `sub16` is placed
  i.check16 24, 0x0007
  let callSite = i.at
  i.call 0                      # patched too
  i.check16 24, 0x0007

  # 15. A counted loop, closed by a backward `brne`.
  i.ldi 18, 10
  i.clr 24
  i.clr 25
  let loopTop = i.at
  i.adiw 24, 3
  i.subi 18, 1
  i.brne loopTop - (i.at + 1)
  i.check16 24, 30

  i.puts "checks ok\n"
  i.ldi 24, exitCode and 0xFF
  i.ldi 25, (exitCode shr 8) and 0xFF
  i.syscall SysExit

  # ── sub16: r25:r24 = 10 - 3, with a frame the caller can see it keep ──────
  let sub16 = i.at
  i.push 28
  i.push 29
  i.ldi 24, 10
  i.ldi 25, 0
  i.ldi 18, 3
  i.ldi 19, 0
  i.sub 24, 18
  i.sbc 25, 19
  i.pop 29
  i.pop 28
  i.ret

  i.w[rcallSite] = uint16(0xD000 or ((sub16 - (rcallSite + 1)) and 0xFFF))
  let (ca, cb) = callWords(sub16)
  i.w[callSite] = uint16(ca)
  i.w[callSite + 1] = uint16(cb)

  var bytes = newSeqOfCap[byte](i.w.len * 2)
  for word in i.w:
    bytes.add byte(word and 0xFF)
    bytes.add byte(word shr 8)
  result = (bytes, checks)

# ── ELF32 ───────────────────────────────────────────────────────────────────

const
  EmAvr = 83
  EfAvrMach5 = 5   ## `e_flags` naming the avr5 instruction set (ATmega328P class)

proc elfImage(code: seq[byte]; entry: int): seq[byte] =
  ## One PT_LOAD at flash address 0. There is no `.data` segment: the probe
  ## builds every value it needs with `ldi`, so nothing depends on the loader
  ## placing initialized data — which is a separate contract, and M6's problem.
  const ehSize = 52
  const phSize = 32
  var o: seq[byte] = @[]
  proc u8(v: int) = o.add byte(v and 0xFF)
  proc u16(v: int) = (u8 v; u8 (v shr 8))
  proc u32(v: int) = (u16 v; u16 (v shr 16))

  u8 0x7F; u8 ord('E'); u8 ord('L'); u8 ord('F')
  u8 1                     # ELFCLASS32
  u8 1                     # ELFDATA2LSB
  u8 1                     # EV_CURRENT
  u8 0; u8 0               # ELFOSABI_NONE, ABI version
  for _ in 0 ..< 7: u8 0   # e_ident padding
  u16 2                    # ET_EXEC
  u16 EmAvr
  u32 1                    # e_version
  u32 entry
  u32 ehSize               # e_phoff
  u32 0                    # e_shoff
  u32 EfAvrMach5           # e_flags
  u16 ehSize
  u16 phSize
  u16 1                    # e_phnum
  u16 40                   # e_shentsize
  u16 0; u16 0             # e_shnum, e_shstrndx

  u32 1                    # PT_LOAD
  u32 ehSize + phSize      # p_offset
  u32 0                    # p_vaddr
  u32 0                    # p_paddr
  u32 code.len             # p_filesz
  u32 code.len             # p_memsz
  u32 5                    # PF_R or PF_X
  u32 2                    # p_align

  result = o & code

proc main =
  if paramCount() < 1:
    quit "usage: avr_probe <out.elf> [exit-code]\n" &
         "  then: bin/avrtest -q -mmcu=avr5 -s 32k <out.elf>"
  let outFile = paramStr(1)
  let exitCode = if paramCount() >= 2: parseInt(paramStr(2)) else: 42
  let (code, checks) = buildImage(exitCode)
  writeFile outFile, elfImage(code, entry = 0)
  echo outFile, ": ", code.len, " bytes, ", checks, " checks, exits ", exitCode

main()
