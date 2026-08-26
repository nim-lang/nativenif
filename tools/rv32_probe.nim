#
#           nativenif — RV32 target probe (milestone R0)
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## Hand-builds a static RV32 Linux ELF that exercises every host facility the
## RISC-V backend's TEST STRATEGY depends on, and nothing else. It predates the
## backend on purpose: if this stops working, the failure is in the target
## contract (QEMU, the syscall ABI, the ELF shape), not in the code generator —
## the same reason `tools/avr_probe.nim` and `tools/cortexm_probe.nim` exist.
##
## Unlike those two this target is HOSTED. `qemu-riscv32` runs a Linux user-mode
## binary, so stdout and the exit status come from `write` and `exit` rather than
## from a simulator's private trap — which makes RV32 the sibling of
## `linux_arm64`, not of `cortex_m`. It also means the generic syscall numbers
## apply: `write` is 64 and `exit` is 93, exactly as on AArch64.
##
## What it proves:
##   * an ELF32 for `EM_RISCV` loads and runs under `qemu-riscv32`
##   * the two PT_LOADs must not share a page. That is the one layout mistake
##     this probe was written to catch: a second mapping decides the page's
##     permissions, so an R+X segment sharing a page with an RW one silently
##     stops being executable and the program dies at its first instruction
##   * the Linux RV32 syscall ABI: number in `a7`, arguments in `a0`..`a5`,
##     `ecall`, result in `a0`
##   * the RV32IM encodings the backend is built from, each checked by computing
##     with it: `lui`+`addi` materialization, `add`/`sub`/`and`, `mul`, `slt`,
##     the immediate shifts, `sw`/`lw` through SP, a backward `bne` loop, and
##     `jal`/`jalr`
##
## The image self-checks: every check exits with its own 1-based index on
## mismatch, so a failure NAMES the broken encoding.
##
## Build & run:
##   nim c -o:bin/rv32_probe tools/rv32_probe.nim
##   bin/rv32_probe /tmp/rv.elf 42
##   qemu-riscv32 /tmp/rv.elf ; echo $?

import std / [os, strutils]

type Img = object
  w: seq[uint32]

proc put(i: var Img; v: uint32) = i.w.add v
proc at(i: Img): int = i.w.len            ## the next WORD index

# ── registers ───────────────────────────────────────────────────────────────
const
  X0 = 0'u32    ## the hardwired zero, and the reason RISC-V needs no `mov`,
                ## no `neg` and no `not`: each is one instruction against it
  RA = 1'u32
  SP = 2'u32
  T0 = 5'u32
  T1 = 6'u32
  T2 = 7'u32
  A0 = 10'u32
  A1 = 11'u32
  A2 = 12'u32
  A7 = 17'u32

# ── encodings ───────────────────────────────────────────────────────────────
# Six formats, and the immediate is scattered differently in four of them. B and
# J are the ones to watch: their immediates are in HALFWORD units with bit 0
# implicit, and the bits are permuted rather than merely shifted.

proc rType(f7, rs2, rs1, f3, rd, op: uint32): uint32 =
  (f7 shl 25) or (rs2 shl 20) or (rs1 shl 15) or (f3 shl 12) or (rd shl 7) or op

proc iType(imm: int32; rs1, f3, rd, op: uint32): uint32 =
  ((uint32(imm) and 0xFFF) shl 20) or (rs1 shl 15) or (f3 shl 12) or (rd shl 7) or op

proc sType(imm: int32; rs2, rs1, f3, op: uint32): uint32 =
  let u = uint32(imm)
  (((u shr 5) and 0x7F) shl 25) or (rs2 shl 20) or (rs1 shl 15) or (f3 shl 12) or
    ((u and 0x1F) shl 7) or op

proc bType(imm: int32; rs2, rs1, f3, op: uint32): uint32 =
  ## `imm[12|10:5]` above and `imm[4:1|11]` below — bit 11 crosses the two halves
  ## and bit 0 does not exist. Reading it as "a shifted offset" is the classic
  ## way to get a branch that lands somewhere plausible.
  let u = uint32(imm)
  (((u shr 12) and 1) shl 31) or (((u shr 5) and 0x3F) shl 25) or
    (rs2 shl 20) or (rs1 shl 15) or (f3 shl 12) or
    (((u shr 1) and 0xF) shl 8) or (((u shr 11) and 1) shl 7) or op

proc uType(imm20, rd, op: uint32): uint32 =
  ((imm20 and 0xFFFFF) shl 12) or (rd shl 7) or op

proc jType(imm: int32; rd, op: uint32): uint32 =
  let u = uint32(imm)
  (((u shr 20) and 1) shl 31) or (((u shr 1) and 0x3FF) shl 21) or
    (((u shr 11) and 1) shl 20) or (((u shr 12) and 0xFF) shl 12) or
    (rd shl 7) or op

proc addi(i: var Img; rd, rs1: uint32; imm: int32) = i.put iType(imm, rs1, 0, rd, 0x13)
proc lui(i: var Img; rd, imm20: uint32) = i.put uType(imm20, rd, 0x37)
proc addR(i: var Img; rd, a, b: uint32) = i.put rType(0, b, a, 0, rd, 0x33)
proc subR(i: var Img; rd, a, b: uint32) = i.put rType(0x20, b, a, 0, rd, 0x33)
proc andR(i: var Img; rd, a, b: uint32) = i.put rType(0, b, a, 7, rd, 0x33)
proc sltR(i: var Img; rd, a, b: uint32) = i.put rType(0, b, a, 2, rd, 0x33)
proc mulR(i: var Img; rd, a, b: uint32) = i.put rType(1, b, a, 0, rd, 0x33)
  ## The `M` extension: RV32I alone has no multiply at all. `rv32im` is the
  ## baseline this backend targets, for the reason avr5 rather than avr2.
proc slli(i: var Img; rd, a: uint32; n: int32) = i.put iType(n, a, 1, rd, 0x13)
proc srai(i: var Img; rd, a: uint32; n: int32) = i.put iType(0x400'i32 or n, a, 5, rd, 0x13)
proc lw(i: var Img; rd, rs1: uint32; off: int32) = i.put iType(off, rs1, 2, rd, 0x03)
proc sw(i: var Img; rs2, rs1: uint32; off: int32) = i.put sType(off, rs2, rs1, 2, 0x23)
proc beq(i: var Img; a, b: uint32; off: int32) = i.put bType(off, b, a, 0, 0x63)
proc bne(i: var Img; a, b: uint32; off: int32) = i.put bType(off, b, a, 1, 0x63)
proc jal(i: var Img; rd: uint32; off: int32) = i.put jType(off, rd, 0x6F)
proc jalr(i: var Img; rd, rs1: uint32; off: int32) = i.put iType(off, rs1, 0, rd, 0x67)
proc ecall(i: var Img) = i.put 0x73'u32

proc liWords(v: int64): int =
  ## How many words a materialization takes, which the caller has to know BEFORE
  ## emitting it whenever a distance is measured across it.
  if v >= -2048 and v < 2048: 1 else: 2

proc li(i: var Img; rd: uint32; v: int64) =
  ## A 32-bit constant. One `addi` against the zero register when it fits twelve
  ## signed bits, otherwise `lui`+`addi` — and the `+0x800` is not decoration:
  ## `addi`'s immediate is SIGNED, so a low half above 0x7FF borrows from the
  ## high half and the `lui` has to be pre-compensated.
  let u = uint32(v and 0xFFFFFFFF)
  if v >= -2048 and v < 2048:
    i.addi(rd, X0, int32(v))
  else:
    let hi = (u + 0x800) shr 12
    let lo = int32(cast[int32](u - (hi shl 12)))
    i.lui(rd, hi and 0xFFFFF)
    i.addi(rd, rd, lo)

proc li2(i: var Img; rd: uint32; v: int64) =
  ## Always TWO words. A value that is not known when its instruction is emitted
  ## must not change size when it becomes known, or every position after it moves.
  let u = uint32(v and 0xFFFFFFFF)
  let hi = (u + 0x800) shr 12
  i.lui(rd, hi and 0xFFFFF)
  i.addi(rd, rd, int32(cast[int32](u - (hi shl 12))))

# ── the image ───────────────────────────────────────────────────────────────

const
  SysWrite = 64
  SysExit = 93
    ## The asm-generic numbers. RV32, RV64 and AArch64 share them, which is why
    ## this target needs no syscall table of its own.
    ##
  LoadBase = 0x10000'u32
  ElfHdr = 52
  PhSize = 32

proc buildCode(dataVa: uint32; msgLen: int; exitCode: int): (Img, int) =
  var i = Img()
  var checks = 0

  proc chk(i: var Img; want: int64; body: proc (i: var Img)) =
    ## Compare `t0` against `want` and exit with this check's index if they
    ## differ. The skip distance is computed from the exit block's own size,
    ## which is why `liWords` has to exist.
    inc checks
    body(i)
    i.li(T1, want)
    let blk = liWords(SysExit) + liWords(int64(checks)) + 1
    i.beq(T0, T1, int32(4 + 4 * blk))
    i.li(A7, SysExit)
    i.li(A0, int64(checks))
    i.ecall()

  # write(1, msg, len)
  i.li(A7, SysWrite)
  i.li(A0, 1)
  i.li2(A1, int64(dataVa))
  i.li(A2, int64(msgLen))
  i.ecall()

  i.chk(30, proc (i: var Img) = (i.li(T0, 10); i.li(T1, 20); i.addR(T0, T0, T1)))
  i.chk(-5, proc (i: var Img) = (i.li(T0, 10); i.li(T1, 15); i.subR(T0, T0, T1)))
  i.chk(0x1234, proc (i: var Img) = i.li(T0, 0x1234))
  # The `lui`+`addi` pair with a low half above 0x7FF — the pre-compensation
  # case, and the one a naive split gets wrong by exactly 0x1000.
  i.chk(cast[int32](0xDEADBEEF'u32), proc (i: var Img) = i.li(T0, 0xDEADBEEF))
  i.chk(600, proc (i: var Img) = (i.li(T0, 200); i.li(T1, 3); i.mulR(T0, T0, T1)))
  i.chk(0x0F, proc (i: var Img) = (i.li(T0, 0xFF); i.li(T1, 0x0F); i.andR(T0, T0, T1)))
  i.chk(1, proc (i: var Img) = (i.li(T0, 5); i.li(T1, 9); i.sltR(T0, T0, T1)))
  i.chk(0, proc (i: var Img) = (i.li(T0, 9); i.li(T1, 5); i.sltR(T0, T0, T1)))
  i.chk(0x100, proc (i: var Img) = (i.li(T0, 1); i.slli(T0, T0, 8)))
  i.chk(-1, proc (i: var Img) = (i.li(T0, -256); i.srai(T0, T0, 8)))
  i.chk(0xCAFE, proc (i: var Img) =
    (i.addi(SP, SP, -16); i.li(T1, 0xCAFE); i.sw(T1, SP, 4);
     i.lw(T0, SP, 4); i.addi(SP, SP, 16)))

  # A counted loop, closed by a BACKWARD branch — the direction whose immediate
  # is easiest to encode wrong, since B-format bit 11 sits below the sign bit.
  i.li(T0, 0)
  i.li(T2, 10)
  let top = i.at
  i.addi(T0, T0, 3)
  i.addi(T2, T2, -1)
  i.bne(T2, X0, int32((top - i.at) * 4))
  i.chk(30, proc (i: var Img) = discard)

  # A call and a return, to a routine placed after the exit.
  let callSite = i.at
  i.put 0                        # patched once the routine is placed
  i.chk(7, proc (i: var Img) = discard)
  i.li(A7, SysExit)
  i.li(A0, int64(exitCode))
  i.ecall()
  let sub = i.at
  i.addi(T0, X0, 7)
  i.jalr(X0, RA, 0)
  i.w[callSite] = jType(int32((sub - callSite) * 4), RA, 0x6F)

  result = (i, checks)

proc elfImage(code: seq[byte]; data: string; exitCode: int): (seq[byte], uint32) =
  ## Two PT_LOADs, and the data one lives a WHOLE PAGE above the code. Sixteen
  ## bytes above would satisfy every field in the header and still fail: two
  ## segments landing in one page have that page's permissions decided by
  ## whichever is mapped last, so an R+X segment sharing a page with an RW one
  ## stops being executable and the program dies at its first instruction.
  const off0 = ElfHdr + PhSize * 2
  let codeVa = LoadBase + uint32(off0)
  let dOff = (off0 + code.len + 15) and not 15
  let dataVa = LoadBase + 0x1000'u32 + uint32(dOff)
  var o: seq[byte] = @[]
  proc u8(v: int) = o.add byte(v and 0xFF)
  proc u16(v: int) = (u8 v; u8 (v shr 8))
  proc u32(v: uint32) = (u16 int(v and 0xFFFF); u16 int((v shr 16) and 0xFFFF))

  u8 0x7F; u8 ord('E'); u8 ord('L'); u8 ord('F')
  u8 1; u8 1; u8 1; u8 0; u8 0
  for _ in 0 ..< 7: u8 0
  u16 2                      # ET_EXEC
  u16 243                    # EM_RISCV
  u32 1'u32
  u32 codeVa                 # e_entry
  u32 uint32(ElfHdr)         # e_phoff
  u32 0'u32                  # e_shoff
  u32 0'u32                  # e_flags: soft float, no compressed instructions
  u16 ElfHdr; u16 PhSize; u16 2; u16 40; u16 0; u16 0

  proc phdr(offset, vaddr, size, flags: uint32) =
    u32 1'u32                # PT_LOAD
    u32 offset; u32 vaddr; u32 vaddr
    u32 size; u32 size
    u32 flags
    u32 0x1000'u32           # p_align: the page the congruence is measured in
  phdr(uint32(off0), codeVa, uint32(code.len), 5)         # R + X
  phdr(uint32(dOff), dataVa, uint32(data.len), 6)         # R + W

  o.add code
  while o.len < dOff: o.add 0'u8
  for ch in data: o.add byte(ch)
  result = (o, dataVa)

proc main =
  if paramCount() < 1:
    quit "usage: rv32_probe <out.elf> [exit-code]\n" &
         "  then: qemu-riscv32 <out.elf> ; echo $?"
  let outFile = paramStr(1)
  let exitCode = if paramCount() >= 2: parseInt(paramStr(2)) else: 42
  const msg = "RISC-V probe\n"

  # Two passes: the data segment's address depends on the code's LENGTH, which
  # depends on the instructions that name that address. `li2` is fixed-width, so
  # one pass with a placeholder and one with the answer agree by construction —
  # and the assertion says so rather than trusting it.
  var (img0, _) = buildCode(0, msg.len, exitCode)
  var probe: seq[byte] = @[]
  for w in img0.w:
    probe.add byte(w and 0xFF); probe.add byte((w shr 8) and 0xFF)
    probe.add byte((w shr 16) and 0xFF); probe.add byte((w shr 24) and 0xFF)
  let (_, dataVa) = elfImage(probe, msg, exitCode)

  let (img, checks) = buildCode(dataVa, msg.len, exitCode)
  doAssert img.w.len == img0.w.len,
    "rv32_probe: the code changed size between the two passes"
  var code: seq[byte] = @[]
  for w in img.w:
    code.add byte(w and 0xFF); code.add byte((w shr 8) and 0xFF)
    code.add byte((w shr 16) and 0xFF); code.add byte((w shr 24) and 0xFF)
  let (image, _) = elfImage(code, msg, exitCode)
  writeFile outFile, image
  when defined(posix):
    discard existsOrCreateDir(".")     # keep std/os imported on every platform
  setFilePermissions(outFile, {fpUserRead, fpUserWrite, fpUserExec,
                               fpGroupRead, fpGroupExec,
                               fpOthersRead, fpOthersExec})
  echo outFile, ": ", code.len, " bytes, ", checks, " checks, exits ", exitCode

main()
