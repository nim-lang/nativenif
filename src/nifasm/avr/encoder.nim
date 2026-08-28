# Nifasm - AVR (avr5) Binary Assembler
# A dependency-free encoder for the AVR instruction set.

## AVR is an 8-bit machine with a 16-bit address space, and both halves of that
## sentence shape this file:
##
##  * **Every instruction is one or two 16-bit words**, stored little-endian. A
##    two-word instruction is two little-endian words, not one little-endian
##    32-bit value — `9200 0210` is written `00 92 10 02`.
##  * **Flash is addressed in WORDS, data in BYTES.** Every branch and call
##    displacement here is a word count, so the relocation patcher divides the
##    byte distance `relocs` computes by two. Getting that wrong produces a
##    branch to exactly half the intended distance, which lands on a real
##    instruction and runs.
##  * **The ALU is 8-bit and destructive**: `add rd, rr` means `rd += rr`. A
##    16-bit add is `add`+`adc` and the carry between them is why the halves
##    cannot be emitted independently — see doc/internals/avr.md.
##
## Three operand restrictions are asserted rather than commented, because each of
## them is a silent wrong-code bug if it reaches the encoding:
##
##  * `ldi`/`subi`/`sbci`/`andi`/`ori`/`cpi` name only r16..r31. The register
##    field is four bits wide and biased by 16, so r0..r15 do not merely fail to
##    encode — they encode as a DIFFERENT register.
##  * `adiw`/`sbiw` name only r24, X, Y and Z, with a 6-bit immediate.
##  * `movw` names only even registers, and `ldd`/`std` only Y and Z.

import ../core/[buffers, relocs]

type
  Register* = enum
    R0 = 0, R1, R2, R3, R4, R5, R6, R7, R8, R9, R10, R11, R12, R13, R14, R15,
    R16, R17, R18, R19, R20, R21, R22, R23, R24, R25, R26, R27, R28, R29, R30, R31

  Pair* = enum
    ## An even-aligned register pair, named by its LOW register — the 16-bit
    ## logical register the code generator allocates. `movw`, `adiw` and `sbiw`
    ## take one of these directly; everything else works on the halves.
    P0 = 0, P2 = 2, P4 = 4, P6 = 6, P8 = 8, P10 = 10, P12 = 12, P14 = 14,
    P16 = 16, P18 = 18, P20 = 20, P22 = 22, P24 = 24, P26 = 26, P28 = 28,
    P30 = 30

  PtrReg* = enum
    ## The three pointer registers, and the whole of AVR's addressing vocabulary.
    ## X has no displaced form, which is why Y is the frame pointer.
    PX, PY, PZ

  Condition* = enum
    ## A branch tests ONE status-register bit, set or clear, so the 14 mnemonics
    ## are 7 flags times 2. The pairs that share an encoding share an entry here:
    ## `brlo` IS `brcs` and `brsh` IS `brcc`, because on this machine an unsigned
    ## comparison leaves its answer in the carry.
    CondEq,      ## Z set     — `breq`
    CondNe,      ## Z clear   — `brne`
    CondLo,      ## C set     — `brlo` / `brcs`, unsigned <
    CondSh,      ## C clear   — `brsh` / `brcc`, unsigned >=
    CondMi,      ## N set     — `brmi`
    CondPl,      ## N clear   — `brpl`
    CondLt,      ## S set     — `brlt`, signed <
    CondGe,      ## S clear   — `brge`, signed >=
    CondVs,      ## V set     — `brvs`
    CondVc,      ## V clear   — `brvc`
    CondHs,      ## H set     — `brhs`
    CondHc,      ## H clear   — `brhc`
    CondTs,      ## T set     — `brts`
    CondTc       ## T clear   — `brtc`

const
  X* = P26
  Y* = P28
  Z* = P30
  SplIo* = 0x3D   ## SP low, in I/O space — reachable only by `in`/`out`
  SphIo* = 0x3E   ## SP high
  SregIo* = 0x3F  ## the status register

  ImmRegs* = {R16..R31}
    ## The registers an immediate form can name. Membership is asserted at every
    ## such encoder, since the field is biased and a low register silently
    ## becomes a high one.
  WordRegs* = {P24, P26, P28, P30}
    ## The pairs `adiw`/`sbiw` reach.

proc invert*(c: Condition): Condition =
  ## The complementary condition. Every condition has one here — unlike the Arm
  ## targets, where `AL` does not — because each is a single flag tested one way
  ## or the other.
  Condition(ord(c) xor 1)

proc flagOf(c: Condition): uint16 =
  ## The SREG bit index a condition tests: C=0, Z=1, N=2, V=3, S=4, H=5, T=6.
  case c
  of CondEq, CondNe: 1
  of CondLo, CondSh: 0
  of CondMi, CondPl: 2
  of CondLt, CondGe: 4
  of CondVs, CondVc: 3
  of CondHs, CondHc: 5
  of CondTs, CondTc: 6

proc testsSet(c: Condition): bool {.inline.} =
  ## Whether the condition branches when the flag is SET (`brbs`) or clear
  ## (`brbc`). The even members of the enum are the "set" ones, which is what
  ## makes `invert` an xor.
  (ord(c) and 1) == 0

# ── emission primitives ─────────────────────────────────────────────────────

proc emit1(dest: var Bytes; w: uint16) {.inline.} =
  ## A one-word instruction, little-endian.
  dest.addUint16 w

proc emit2(dest: var Bytes; hi, lo: uint16) {.inline.} =
  ## A two-word instruction: the opcode word first, then its immediate word.
  ## Both little-endian, in that order.
  dest.addUint16 hi
  dest.addUint16 lo

proc r(x: Register): uint16 {.inline.} = uint16(ord(x))
proc p(x: Pair): uint16 {.inline.} = uint16(ord(x))

proc rr(d, s: Register): uint16 {.inline.} =
  ## The `dddd d` / `rrrr r` scattering shared by every 2-register ALU form:
  ## bit 9 is the source's high bit, bit 8 the destination's.
  ((r(s) and 0x10) shl 5) or ((r(d) and 0x1F) shl 4) or (r(s) and 0xF)

proc rk(d: Register; k: int): uint16 {.inline.} =
  ## The `KKKK dddd KKKK` scattering shared by every immediate form.
  assert d in ImmRegs
  ((uint16(k) shr 4) and 0xF) shl 8 or ((r(d) - 16) shl 4) or (uint16(k) and 0xF)

# ── moves and immediates ────────────────────────────────────────────────────

proc emitLdi*(dest: var Bytes; rd: Register; k: int) =
  ## LDI rd, K — the only way to get a constant into a register, and it does not
  ## reach r0..r15.
  dest.emit1 0xE000'u16 or rk(rd, k)

proc emitMov*(dest: var Bytes; rd, rs: Register) =
  dest.emit1 0x2C00'u16 or rr(rd, rs)

proc emitMovw*(dest: var Bytes; pd, ps: Pair) =
  ## MOVW pd, ps — a whole 16-bit logical register in one instruction. This is
  ## what makes the pair model cheap rather than a two-instruction fiction.
  dest.emit1 0x0100'u16 or ((p(pd) shr 1) shl 4) or (p(ps) shr 1)

proc emitClr*(dest: var Bytes; rd: Register) =
  ## CLR rd IS `eor rd, rd`. Also how r1 is put back to zero after a `mul`.
  dest.emit1 0x2400'u16 or rr(rd, rd)

proc emitSer*(dest: var Bytes; rd: Register) =
  ## SER rd IS `ldi rd, 0xFF`.
  dest.emitLdi(rd, 0xFF)

# ── 8-bit ALU, register-register ────────────────────────────────────────────
# All destructive: the destination is also the first source.

proc emitAdd*(dest: var Bytes; rd, rs: Register) = dest.emit1 0x0C00'u16 or rr(rd, rs)
proc emitAdc*(dest: var Bytes; rd, rs: Register) = dest.emit1 0x1C00'u16 or rr(rd, rs)
proc emitSub*(dest: var Bytes; rd, rs: Register) = dest.emit1 0x1800'u16 or rr(rd, rs)
proc emitSbc*(dest: var Bytes; rd, rs: Register) = dest.emit1 0x0800'u16 or rr(rd, rs)
proc emitAnd*(dest: var Bytes; rd, rs: Register) = dest.emit1 0x2000'u16 or rr(rd, rs)
proc emitOr*(dest: var Bytes; rd, rs: Register) = dest.emit1 0x2800'u16 or rr(rd, rs)
proc emitEor*(dest: var Bytes; rd, rs: Register) = dest.emit1 0x2400'u16 or rr(rd, rs)
proc emitCp*(dest: var Bytes; rd, rs: Register) = dest.emit1 0x1400'u16 or rr(rd, rs)
proc emitCpc*(dest: var Bytes; rd, rs: Register) = dest.emit1 0x0400'u16 or rr(rd, rs)
proc emitCpse*(dest: var Bytes; rd, rs: Register) = dest.emit1 0x1000'u16 or rr(rd, rs)

proc emitTst*(dest: var Bytes; rd: Register) =
  ## TST rd IS `and rd, rd` — it sets Z and N without changing the register.
  dest.emitAnd(rd, rd)

proc emitLsl*(dest: var Bytes; rd: Register) =
  ## LSL rd IS `add rd, rd`. There is no multi-bit shift on this machine: a shift
  ## by n is n of these, and a variable shift is a loop.
  dest.emitAdd(rd, rd)

proc emitRol*(dest: var Bytes; rd: Register) =
  ## ROL rd IS `adc rd, rd` — the carry-in half of a 16-bit left shift.
  dest.emitAdc(rd, rd)

proc emitMul*(dest: var Bytes; rd, rs: Register) =
  ## MUL rd, rs — 8x8 unsigned, and the product lands in the FIXED pair r1:r0.
  ## That is the one reason r1:r0 cannot be an allocatable pair, and every `mul`
  ## must be followed by a `clr r1` to restore the zero register.
  dest.emit1 0x9C00'u16 or rr(rd, rs)

proc emitMuls*(dest: var Bytes; rd, rs: Register) =
  ## MULS — signed, and both operands must be r16..r31.
  assert rd in ImmRegs and rs in ImmRegs
  dest.emit1 0x0200'u16 or ((r(rd) - 16) shl 4) or (r(rs) - 16)

# ── 8-bit ALU, register-immediate ───────────────────────────────────────────
# r16..r31 only. There is no `addi`: adding a constant means subtracting its
# negation, which is why `subi` carries the weight here.

proc emitSubi*(dest: var Bytes; rd: Register; k: int) = dest.emit1 0x5000'u16 or rk(rd, k)
proc emitSbci*(dest: var Bytes; rd: Register; k: int) = dest.emit1 0x4000'u16 or rk(rd, k)
proc emitAndi*(dest: var Bytes; rd: Register; k: int) = dest.emit1 0x7000'u16 or rk(rd, k)
proc emitOri*(dest: var Bytes; rd: Register; k: int) = dest.emit1 0x6000'u16 or rk(rd, k)
proc emitCpi*(dest: var Bytes; rd: Register; k: int) = dest.emit1 0x3000'u16 or rk(rd, k)

# ── 16-bit forms on a pair ──────────────────────────────────────────────────

proc fitsWordImm*(k: int): bool {.inline.} = k in 0..63
  ## Whether `adiw`/`sbiw` can carry this constant. Outside it the caller must
  ## fall back to `subi`+`sbci`, which needs an `ldi`-capable pair anyway.

proc emitAdiw*(dest: var Bytes; pd: Pair; k: int) =
  ## ADIW pd, K — 0..63 added to a whole pair, on the four upper pairs only.
  assert pd in WordRegs and fitsWordImm(k)
  dest.emit1 0x9600'u16 or ((uint16(k) and 0x30) shl 2) or
             (((p(pd) - 24) shr 1) shl 4) or (uint16(k) and 0xF)

proc emitSbiw*(dest: var Bytes; pd: Pair; k: int) =
  assert pd in WordRegs and fitsWordImm(k)
  dest.emit1 0x9700'u16 or ((uint16(k) and 0x30) shl 2) or
             (((p(pd) - 24) shr 1) shl 4) or (uint16(k) and 0xF)

# ── unary ───────────────────────────────────────────────────────────────────

proc emitCom*(dest: var Bytes; rd: Register) = dest.emit1 0x9400'u16 or (r(rd) shl 4)
proc emitNeg*(dest: var Bytes; rd: Register) = dest.emit1 0x9401'u16 or (r(rd) shl 4)
proc emitSwap*(dest: var Bytes; rd: Register) = dest.emit1 0x9402'u16 or (r(rd) shl 4)
proc emitInc*(dest: var Bytes; rd: Register) = dest.emit1 0x9403'u16 or (r(rd) shl 4)
proc emitAsr*(dest: var Bytes; rd: Register) = dest.emit1 0x9405'u16 or (r(rd) shl 4)
proc emitLsr*(dest: var Bytes; rd: Register) = dest.emit1 0x9406'u16 or (r(rd) shl 4)
proc emitRor*(dest: var Bytes; rd: Register) = dest.emit1 0x9407'u16 or (r(rd) shl 4)
proc emitDec*(dest: var Bytes; rd: Register) = dest.emit1 0x940A'u16 or (r(rd) shl 4)

# ── memory ──────────────────────────────────────────────────────────────────

proc ptrNibble(pr: PtrReg): uint16 {.inline.} =
  ## The low nibble selecting the pointer register in the 0x9000-based forms —
  ## plain `ld X`, and the post-increment forms for all three.
  case pr
  of PX: 0xC
  of PY: 0x8
  of PZ: 0x0

proc fitsDisp*(q: int): bool {.inline.} = q in 0..63
  ## Whether a frame slot is reachable as `Y+q`. Beyond 63 the pointer itself has
  ## to be advanced first, which is `adiw` or `subi`+`sbci`.

proc dispBits(q: int): uint16 {.inline.} =
  ## `q` is scattered across bits 13, 11:10 and 2:0 — the widest scattering in
  ## the instruction set, and the easiest of these encodings to get wrong.
  ((uint16(q) and 0x20) shl 8) or ((uint16(q) and 0x18) shl 7) or (uint16(q) and 0x7)

proc emitLdd*(dest: var Bytes; rd: Register; pr: PtrReg; q: int) =
  ## LDD rd, Y+q / Z+q — displacement 0..63. X has no displaced form at all.
  assert pr != PX and fitsDisp(q)
  dest.emit1 0x8000'u16 or dispBits(q) or (r(rd) shl 4) or (if pr == PY: 0x8 else: 0x0)

proc emitStd*(dest: var Bytes; pr: PtrReg; q: int; rs: Register) =
  ## STD Y+q, rs / Z+q, rs
  assert pr != PX and fitsDisp(q)
  dest.emit1 0x8200'u16 or dispBits(q) or (r(rs) shl 4) or (if pr == PY: 0x8 else: 0x0)

proc emitLd*(dest: var Bytes; rd: Register; pr: PtrReg) =
  ## LD rd, X|Y|Z.
  ##
  ## Y and Z have no plain form of their own: `ld rd, Z` IS `ldd rd, Z+0`, on the
  ## 0x8000 opcode. Only X is on 0x9000 — and 0x9000 with a Z nibble of 0 is
  ## `lds`, a TWO-word direct load that would swallow the following instruction
  ## as its address operand. That is what the encoder self-test caught.
  if pr == PX: dest.emit1 0x900C'u16 or (r(rd) shl 4)
  else: dest.emitLdd(rd, pr, 0)

proc emitSt*(dest: var Bytes; pr: PtrReg; rs: Register) =
  ## ST X|Y|Z, rs — and `st Z, rs` IS `std Z+0, rs`, as above.
  if pr == PX: dest.emit1 0x920C'u16 or (r(rs) shl 4)
  else: dest.emitStd(pr, 0, rs)

proc emitLdInc*(dest: var Bytes; rd: Register; pr: PtrReg) =
  ## LD rd, X+|Y+|Z+ — post-increment. What a byte-at-a-time aggregate copy walks
  ## with, and here all three ARE on the 0x9000 opcode.
  dest.emit1 0x9001'u16 or (r(rd) shl 4) or ptrNibble(pr)
proc emitStInc*(dest: var Bytes; pr: PtrReg; rs: Register) =
  ## ST X+|Y+|Z+, rs
  dest.emit1 0x9201'u16 or (r(rs) shl 4) or ptrNibble(pr)

proc emitLds*(dest: var Bytes; rd: Register; address: int) =
  ## LDS rd, k — a 16-bit direct address, in two words. Twice the size of the
  ## indirect form, but it needs none of the three pointer registers.
  dest.emit2(0x9000'u16 or (r(rd) shl 4), uint16(address and 0xFFFF))

proc emitSts*(dest: var Bytes; address: int; rs: Register) =
  ## STS k, rs
  dest.emit2(0x9200'u16 or (r(rs) shl 4), uint16(address and 0xFFFF))

proc emitPush*(dest: var Bytes; rs: Register) = dest.emit1 0x920F'u16 or (r(rs) shl 4)
proc emitPop*(dest: var Bytes; rd: Register) = dest.emit1 0x900F'u16 or (r(rd) shl 4)

proc emitIn*(dest: var Bytes; rd: Register; io: int) =
  ## IN rd, A — the I/O address space, which is where SP and SREG live and the
  ## only way to reach them.
  assert io in 0..63
  dest.emit1 0xB000'u16 or ((uint16(io) and 0x30) shl 5) or (r(rd) shl 4) or (uint16(io) and 0xF)

proc emitOut*(dest: var Bytes; io: int; rs: Register) =
  assert io in 0..63
  dest.emit1 0xB800'u16 or ((uint16(io) and 0x30) shl 5) or (r(rs) shl 4) or (uint16(io) and 0xF)

proc emitLpm*(dest: var Bytes; rd: Register; postInc: bool) =
  ## LPM rd, Z(+) — the ONLY way to read program memory, which is a separate
  ## address space from data. See "Constants" in doc/internals/avr.md for why
  ## nothing here puts a string in flash yet.
  dest.emit1 (if postInc: 0x9005'u16 else: 0x9004'u16) or (r(rd) shl 4)

# ── control flow, no relocation ─────────────────────────────────────────────

proc emitRet*(dest: var Bytes) = dest.emit1 0x9508'u16
proc emitReti*(dest: var Bytes) = dest.emit1 0x9518'u16
proc emitNop*(dest: var Bytes) = dest.emit1 0x0000'u16
proc emitSleep*(dest: var Bytes) = dest.emit1 0x9588'u16
proc emitBreak*(dest: var Bytes) = dest.emit1 0x9598'u16
proc emitWdr*(dest: var Bytes) = dest.emit1 0x95A8'u16
proc emitSei*(dest: var Bytes) = dest.emit1 0x9478'u16
proc emitCli*(dest: var Bytes) = dest.emit1 0x94F8'u16

proc emitIjmp*(dest: var Bytes) = dest.emit1 0x9409'u16
  ## IJMP — jump to the address in Z. An indirect tail call.
proc emitIcall*(dest: var Bytes) = dest.emit1 0x9509'u16
  ## ICALL — call the address in Z. The only indirect call, so a function
  ## pointer must be in Z at the call, and Z is therefore never a value's home.

proc emitSbrc*(dest: var Bytes; rs: Register; bit: int) =
  ## SBRC rs, b — skip the next instruction if bit b of rs is clear.
  assert bit in 0..7
  dest.emit1 0xFC00'u16 or (r(rs) shl 4) or uint16(bit)
proc emitSbrs*(dest: var Bytes; rs: Register; bit: int) =
  assert bit in 0..7
  dest.emit1 0xFE00'u16 or (r(rs) shl 4) or uint16(bit)

# ── control flow, relocated ─────────────────────────────────────────────────
# Reach is the thing to watch here, and it is short. `rjmp`/`rcall` carry 12
# signed WORD bits — ±4 KB of flash — and a conditional branch carries 7, which
# is ±128 bytes. A 32 KB part therefore cannot assume a call is in range, which
# is why `emitCall`/`emitJmp` (two words, a 22-bit absolute word address) are the
# default form and the relative ones are the optimization.

proc emitRjmp*(dest: var Buffer; target: LabelId) =
  ## RJMP target — one word, ±4 KB.
  let pos = dest.data.len
  dest.addReloc(pos, target, rkAvrRjmp, 2)
  dest.data.emit1 0xC000'u16

proc emitRcall*(dest: var Buffer; target: LabelId) =
  ## RCALL target — one word, ±4 KB.
  let pos = dest.data.len
  dest.addReloc(pos, target, rkAvrRcall, 2)
  dest.data.emit1 0xD000'u16

proc emitJmp*(dest: var Buffer; target: LabelId) =
  ## JMP target — two words, an absolute 22-bit WORD address, so it reaches all
  ## of flash on any part this backend targets.
  let pos = dest.data.len
  dest.addReloc(pos, target, rkAvrJmp, 4)
  dest.data.emit2(0x940C'u16, 0)

proc emitCall*(dest: var Buffer; target: LabelId) =
  ## CALL target — two words, absolute.
  let pos = dest.data.len
  dest.addReloc(pos, target, rkAvrCall, 4)
  dest.data.emit2(0x940E'u16, 0)

proc emitBranch*(dest: var Buffer; cond: Condition; target: LabelId) =
  ## BR<cond> target — one word, ±128 BYTES. The narrowest reach in the
  ## instruction set: a loop body of more than about sixty instructions cannot be
  ## closed by one, and the selector has to invert the condition and branch over
  ## an `rjmp` instead.
  ##
  ## The condition rides in the instruction rather than in the relocation kind:
  ## the patcher preserves every bit but the seven displacement bits, so one kind
  ## covers all fourteen.
  let pos = dest.data.len
  dest.addReloc(pos, target, rkAvrBrcond, 2)
  let base = if testsSet(cond): 0xF000'u16 else: 0xF400'u16
  dest.data.emit1 base or flagOf(cond)

proc emitLdiAddr*(dest: var Buffer; pd: Pair; target: LabelId) =
  ## LDI lo / LDI hi — materialize a label's absolute DATA address into a pair,
  ## patched once the layout is fixed. Two `ldi`s, so the pair must be
  ## `ldi`-capable; that is every pair the allocator can reach anyway.
  ##
  ## This is the AVR twin of Cortex-M's MOVW+MOVT pair, and it is fixed-size for
  ## the same reason: patching must never resize an instruction.
  assert Register(ord(pd)) in ImmRegs
  let pos = dest.data.len
  dest.addReloc(pos, target, rkAvrLdiAddr, 4)
  dest.data.emitLdi(Register(ord(pd)), 0)
  dest.data.emitLdi(Register(ord(pd) + 1), 0)
