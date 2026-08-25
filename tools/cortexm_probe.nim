#
#           nativenif — Cortex-M target probe (milestone M0)
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## Hand-builds a bare-metal Cortex-M4 ELF32 image that exercises every host
## facility the Cortex-M backend's TEST STRATEGY depends on, and nothing else.
## It predates `codegen_m`/`thumb2` on purpose: if this stops working, the
## failure is in the target contract (QEMU, semihosting, the boot protocol),
## not in the code generator — which is exactly the distinction that is
## impossible to make once a 6000-line backend sits in between.
##
## What it proves:
##   * the M-profile boot protocol — a vector table at 0x00000000 whose word 0
##     is the initial MSP and word 1 the reset handler WITH the Thumb bit set
##   * Thumb-2 encodings emitted by hand (MOVW/MOVT/MOV-imm/STR-imm/BKPT/B)
##   * ARM semihosting via `bkpt #0xAB`: SYS_WRITE0, SYS_OPEN(":tt")+SYS_WRITE,
##     and SYS_EXIT_EXTENDED carrying an exit STATUS (plain SYS_EXIT cannot —
##     on 32-bit its r1 is the reason code itself, not a pointer to a block)
##   * that QEMU forwards that status as its own process exit status, which is
##     what lets `tests/arkham/*.exitcode` fixtures work unchanged
##
## Build & run:
##   nim c -o:bin/cortexm_probe tools/cortexm_probe.nim
##   bin/cortexm_probe /tmp/probe.elf 42
##   qemu-system-arm -M mps2-an386 -cpu cortex-m4 -display none -serial none \
##     -monitor none -chardev stdio,id=semi \
##     -semihosting-config enable=on,target=native,chardev=semi -kernel /tmp/probe.elf
##
## The `-chardev stdio` routing is NOT optional: with a bare
## `-semihosting-config enable=on,target=native` QEMU writes the semihosting
## console to its own STDERR, where it would be interleaved with QEMU's
## diagnostics and could not be compared against a fixture's expected stdout.

import std / [os, strutils]

type Img = object
  d: seq[byte]

proc u8(i: var Img; v: int) = i.d.add byte(v and 0xFF)
proc u16(i: var Img; v: int) = (i.u8 v; i.u8 (v shr 8))
proc u32(i: var Img; v: int) = (i.u16 v; i.u16 (v shr 16))
proc str0(i: var Img; s: string) =
  for c in s: i.u8 ord(c)
  i.u8 0

# ── Thumb-2 encodings ───────────────────────────────────────────────────────
# Hand-rolled here rather than imported: this tool must stay independent of
# `nifasm/thumb2`, so it can arbitrate whether a failure is ours or the host's.

proc movwt(i: var Img; rd, imm16: int; isMovt: bool) =
  ## MOVW (T3) / MOVT (T1). The 16-bit immediate is split imm4:i:imm3:imm8 —
  ## a scattering that makes these the easiest Thumb-2 encodings to get wrong.
  let imm4 = (imm16 shr 12) and 0xF
  let ib   = (imm16 shr 11) and 0x1
  let imm3 = (imm16 shr 8) and 0x7
  let imm8 = imm16 and 0xFF
  i.u16 (if isMovt: 0xF2C0 else: 0xF240) or (ib shl 10) or imm4
  i.u16 (imm3 shl 12) or (rd shl 8) or imm8

proc ldr32(i: var Img; rd, v: int) =
  ## Materialize a full 32-bit constant: MOVW then MOVT. No literal pool, so
  ## nothing here depends on PC-relative reach.
  i.movwt(rd, v and 0xFFFF, isMovt = false)
  i.movwt(rd, (v shr 16) and 0xFFFF, isMovt = true)

proc movsImm(i: var Img; rd, imm8: int) =
  ## MOV (immediate) T1, 16-bit: `00100 Rd imm8`.
  i.u16 0x2000 or (rd shl 8) or (imm8 and 0xFF)

proc strImm(i: var Img; rt, rn, wordOff: int) =
  ## STR (immediate) T1, 16-bit: `01100 imm5 Rn Rt`, byte offset = imm5*4.
  ## Low registers only — sufficient for building a semihosting param block.
  i.u16 0x6000 or (wordOff shl 6) or (rn shl 3) or rt

proc bkpt(i: var Img; imm8: int) =
  ## BKPT T1, 16-bit: `10111110 imm8`. With imm8 = 0xAB this IS the semihosting
  ## call on M-profile (A-profile uses `svc 0x123456` instead).
  i.u16 0xBE00 or (imm8 and 0xFF)

proc bSelf(i: var Img) =
  ## B (T2) branching to itself: offset -4, so imm11 = 0x7FE. The canonical
  ## `b .` trap that catches a reset handler which somehow returns.
  i.u16 0xE7FE

# ── ARM semihosting ─────────────────────────────────────────────────────────

const
  SysOpen*  = 0x01
  SysWrite0* = 0x04   ## r1 = pointer to a NUL-terminated string
  SysWrite*  = 0x05   ## r1 = &{handle, buf, len}; returns bytes NOT written
  SysExitExtended* = 0x20  ## r1 = &{reason, status}
  AdpStoppedApplicationExit* = 0x20026
  SemiBkpt* = 0xAB

proc semihost(i: var Img; op, blockAddr: int) =
  i.ldr32 1, blockAddr
  i.movsImm 0, op
  i.bkpt SemiBkpt

# ── image layout ────────────────────────────────────────────────────────────

const
  InitialSp* = 0x20010000
    ## MPS2 SSRAM2/3 lives at 0x20000000; the stack starts 64K in and grows down.
  CodeVa* = 8
    ## Right after the two vector-table words this probe actually needs. A real
    ## image needs the full exception table here; nothing in the probe faults.
  DataVa = 0x100
    ## Data parked well past the code so both can be laid out in one pass.

proc buildImage(exitCode: int): seq[byte] =
  const
    msgA = "A ok: SYS_WRITE0\n"
    msgB = "B ok: SYS_OPEN + SYS_WRITE\n"
  var dv = DataVa
  let ttNameVa = dv   ; dv += 4    # ":tt\0"
  let openBlkVa = dv  ; dv += 12   # {name, mode, namelen}
  let msgAVa = dv     ; dv += 32
  let msgBVa = dv     ; dv += 32
  let writeBlkVa = dv ; dv += 12   # {handle, buf, len}
  let exitBlkVa = dv  ; dv += 8    # {reason, status}

  var i = Img()
  i.u32 InitialSp                  # vector 0: initial MSP
  i.u32 CodeVa or 1                # vector 1: reset handler | Thumb bit

  # A: the simple console write — no handle, no param block.
  i.semihost SysWrite0, msgAVa

  # B: the form a real `write(fd, buf, len)` lowers to. QEMU happens to accept a
  # RAW fd 1 here, but a hardware debug probe does not: handles come from
  # SYS_OPEN, so the backend opens ":tt" once at entry and caches the result.
  i.semihost SysOpen, openBlkVa    # r0 = stdout handle
  i.ldr32 2, writeBlkVa
  i.strImm 0, 2, 0                 # blk[0] = handle
  i.ldr32 3, msgBVa
  i.strImm 3, 2, 1                 # blk[1] = buf
  i.movsImm 3, msgB.len
  i.strImm 3, 2, 2                 # blk[2] = len
  i.semihost SysWrite, writeBlkVa

  i.semihost SysExitExtended, exitBlkVa
  i.bSelf                          # unreachable: SYS_EXIT does not return

  doAssert i.d.len <= ttNameVa, "code overran the data area at " & $i.d.len
  while i.d.len < ttNameVa: i.u8 0

  i.str0 ":tt"
  doAssert i.d.len == openBlkVa
  i.u32 ttNameVa
  i.u32 4                          # mode 4 == "w"
  i.u32 len(":tt")
  doAssert i.d.len == msgAVa
  let aAt = i.d.len
  i.str0 msgA
  while i.d.len < aAt + 32: i.u8 0
  doAssert i.d.len == msgBVa
  let bAt = i.d.len
  i.str0 msgB
  while i.d.len < bAt + 32: i.u8 0
  doAssert i.d.len == writeBlkVa
  i.u32 0; i.u32 0; i.u32 0
  doAssert i.d.len == exitBlkVa
  i.u32 AdpStoppedApplicationExit
  i.u32 exitCode
  result = i.d

# ── ELF32 / EM_ARM wrapper ──────────────────────────────────────────────────

const
  EhdrSize = 52
  PhdrSize = 32
  ET_EXEC = 2
  EM_ARM = 40
  PT_LOAD = 1
  EF_ARM_EABI_VER5 = 0x05000000

proc wrapElf32(image: seq[byte]; entryVa: int): seq[byte] =
  ## A single PT_LOAD covering the whole image at vaddr 0. NOTE the ELF32 program
  ## header orders its fields type/offset/vaddr/paddr/filesz/memsz/FLAGS/align —
  ## ELF64 puts flags immediately after type, and swapping the two yields a header
  ## that loads as garbage.
  let off = EhdrSize + PhdrSize
  var e = Img()
  e.u8 0x7F; e.u8 ord('E'); e.u8 ord('L'); e.u8 ord('F')
  e.u8 1                      # ELFCLASS32
  e.u8 1                      # ELFDATA2LSB
  e.u8 1                      # EV_CURRENT
  for _ in 0 ..< 9: e.u8 0    # padding
  e.u16 ET_EXEC
  e.u16 EM_ARM
  e.u32 1                     # e_version
  e.u32 entryVa or 1          # e_entry, Thumb bit set
  e.u32 EhdrSize              # e_phoff
  e.u32 0                     # e_shoff
  e.u32 EF_ARM_EABI_VER5      # e_flags
  e.u16 EhdrSize; e.u16 PhdrSize; e.u16 1
  e.u16 40; e.u16 0; e.u16 0
  doAssert e.d.len == EhdrSize
  e.u32 PT_LOAD
  e.u32 off
  e.u32 0                     # p_vaddr
  e.u32 0                     # p_paddr
  e.u32 image.len             # p_filesz
  e.u32 image.len             # p_memsz
  e.u32 7                     # PF_R or PF_W or PF_X
  e.u32 4                     # p_align
  doAssert e.d.len == off
  e.d.add image
  result = e.d

when isMainModule:
  let outFile = if paramCount() >= 1: paramStr(1) else: "cortexm_probe.elf"
  let exitCode = if paramCount() >= 2: parseInt(paramStr(2)) else: 42
  writeFile(outFile, wrapElf32(buildImage(exitCode), CodeVa))
  echo "wrote ", outFile, " (expect exit status ", exitCode, ")"
