#
#           nifasm — DWARF call-frame information (.eh_frame)
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## The unwind tables a debugger needs to walk a stack that has no frame
## pointers, and the model behind them.
##
## Everything here rests on ONE property of arkham's code, stated in
## `src/arkham/design.md`: *the frame is fixed* — the prologue lowers SP once
## and SP is then constant until the epilogue. A general compiler needs DWARF
## CFI because its stack pointer moves inside the body, so the CFA rule has to
## be a per-PC program; here it is a per-PROC constant plus the handful of
## states the prologue passes through. That is why this file is small and why
## it needs no expression evaluator: `CfiStep` is "after this many bytes, the
## CFA is SP+N, and these registers sit at these offsets from it", and one proc
## has as many of those as it has prologue instructions.
##
## What the collector hands over (`ProcUnwind`) is deliberately arch-neutral;
## only the DWARF register NUMBERS and the initial CFA rule differ per target,
## and both are confined to `cieFor`/the collector's `dwarfReg*` helpers.
##
## Encoding notes, since the format has three near-identical variants:
##  * this is `.eh_frame` (CIE id 0, FDE's CIE pointer is a BACKWARD distance),
##    not `.debug_frame` (CIE id 0xffffffff, absolute section offset);
##  * addresses use `DW_EH_PE_absptr`, so the section needs no relocation: an FDE
##    names its proc's absolute vaddr outright. The usual `pcrel` encoding would
##    compute that from the section's own runtime address, which buys nothing here
##    (the image is not PIE) and costs a reader that has to know where the section
##    landed. `absptr` is therefore correct whether or not the section is mapped —
##    which matters, because it IS mapped: the ELF writer gives `.eh_frame` a
##    read-only `PT_LOAD` of its own, since valgrind rejects CFI it cannot place in
##    a loaded segment. See the segment comment in `assembler.nim`.

import std / [assertions, algorithm]
import tracetable
export tracetable

type
  CfiSave* = object
    ## "register `reg` is saved at CFA + `cfaOff`" (`cfaOff` is negative).
    ##
    ## `reg` is the register's MACHINE number (the encoding order: x86-64's
    ## rax=0, rcx=1, rdx=2, rbx=3…; AArch64's x0=0…x30=30), never a format's own
    ## numbering. DWARF permutes the x86-64 ones and offsets the AArch64 vector
    ## ones; `.xdata` uses the machine numbers as they are. Keeping the FACT
    ## machine-shaped and each encoder's numbering inside that encoder is what
    ## stops one format's convention leaking into the other.
    reg*: int32
    isFloat*: bool
    cfaOff*: int32

  CfiStep* = object
    ## The unwind state *after* one prologue instruction.
    at*: int              ## code position (byte offset in the text image) just
                          ## past the instruction this step describes
    cfaOff*: int32        ## CFA = SP + this, from `at` onward
    saves*: seq[CfiSave]  ## registers this instruction spilled
    ssizeSlot*: bool      ## the CFA delta is the frame size, which nifasm only
                          ## knows once the proc's slots are laid out; the
                          ## collector fills `cfaOff` in at that point
    frameImm*: int32      ## the literal immediate this instruction carried: the
                          ## `(ssize N)` alignment pad when `ssizeSlot`, the plain
                          ## `sub rsp, N` otherwise. The CFA offset alone cannot
                          ## reconstruct it once `pass2Proc` folds the frame size
                          ## in, and `(popframe)` has to re-emit the SAME
                          ## instruction the prologue did.

  ProcUnwind* = object
    name*: string         ## the NIF symbol — what a `bt` frame is labelled with
    start*, stop*: int    ## code positions of the proc's first and one-past-last byte
    steps*: seq[CfiStep]

  DwarfArch* = enum
    dwX64, dwA64

const
  # CFA opcodes (DWARF 5 §6.4.2). Only the six shapes a fixed frame needs.
  DW_CFA_nop = 0x00'u8
  DW_CFA_advance_loc1 = 0x02'u8
  DW_CFA_advance_loc2 = 0x03'u8
  DW_CFA_advance_loc4 = 0x04'u8
  DW_CFA_undefined = 0x07'u8
  DW_CFA_def_cfa = 0x0c'u8
  DW_CFA_def_cfa_offset = 0x0e'u8
  DW_CFA_advance_loc_hi = 0x40'u8   ## | delta, delta < 64
  DW_CFA_offset_hi = 0x80'u8        ## | reg,   reg < 64

  DW_EH_PE_absptr = 0x00'u8

  DwarfRaX64* = 16'i32   ## x86-64's return-address column: the pushed RIP
  DwarfRaA64* = 30'i32   ## AArch64's: the link register
  DwarfSpX64* = 7'i32
  DwarfSpA64* = 31'i32

proc addU8(b: var seq[byte]; v: uint8) = b.add v
proc addU16(b: var seq[byte]; v: uint16) =
  b.add byte(v and 0xFF); b.add byte((v shr 8) and 0xFF)
proc addU32(b: var seq[byte]; v: uint32) =
  for i in 0 ..< 4: b.add byte((v shr (8 * i)) and 0xFF)
proc addU64(b: var seq[byte]; v: uint64) =
  for i in 0 ..< 8: b.add byte((v shr (8 * i)) and 0xFF)

proc addUleb(b: var seq[byte]; v0: uint64) =
  var v = v0
  while true:
    var c = byte(v and 0x7F)
    v = v shr 7
    if v != 0: c = c or 0x80
    b.add c
    if v == 0: break

proc addSleb(b: var seq[byte]; v0: int64) =
  var v = v0
  while true:
    var c = byte(v and 0x7F)
    let signBit = (c and 0x40) != 0
    v = v shr 7                        # arithmetic shift: sign-propagating
    let done = (v == 0 and not signBit) or (v == -1 and signBit)
    if not done: c = c or 0x80
    b.add c
    if done: break

proc advanceLoc(b: var seq[byte]; delta: int) =
  ## `DW_CFA_advance_loc*`, narrowest form that fits. The code alignment factor
  ## is 1 on both targets (x86-64 has variable-length instructions; on AArch64 a
  ## factor of 4 would save a byte or two and buy nothing).
  assert delta >= 0
  if delta < 64:
    b.addU8 DW_CFA_advance_loc_hi or uint8(delta)
  elif delta <= 0xFF:
    b.addU8 DW_CFA_advance_loc1; b.addU8 uint8(delta)
  elif delta <= 0xFFFF:
    b.addU8 DW_CFA_advance_loc2; b.addU16 uint16(delta)
  else:
    b.addU8 DW_CFA_advance_loc4; b.addU32 uint32(delta)

proc dwarfNum(sv: CfiSave; arch: DwarfArch): int32 =
  ## The machine register number in DWARF's numbering.
  ##
  ## x86-64 is the awkward one: DWARF orders rax, rdx, rcx, rbx, rsi, rdi, rbp,
  ## rsp while the ENCODING orders rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi. The
  ## two agree only from r8 up, and a wrong permutation names one live
  ## register's saved slot as another's — which reads as a plausible backtrace,
  ## not as an error. AArch64 needs no permutation; its vector registers just
  ## live at 64..95.
  const x64Map = [0'i32, 2, 1, 3, 7, 6, 4, 5, 8, 9, 10, 11, 12, 13, 14, 15]
  case arch
  of dwX64:
    if sv.reg >= 0 and sv.reg < 16: x64Map[sv.reg] else: sv.reg
  of dwA64:
    if sv.isFloat: 64'i32 + sv.reg else: sv.reg

proc cieFor(arch: DwarfArch): seq[byte] =
  ## The single CIE both targets' FDEs point at: the state at a proc's ENTRY.
  ##
  ## x86-64 — the `call` pushed the return address, so CFA = SP+8 and the RA is
  ## at CFA-8. AArch64 — nothing is on the stack yet: CFA = SP+0 and the RA is
  ## live in the link register, which is DWARF's default rule for a column with
  ## no entry, so it is stated by `return_address_register` alone.
  var ins: seq[byte] = @[]
  case arch
  of dwX64:
    ins.addU8 DW_CFA_def_cfa; ins.addUleb uint64(DwarfSpX64); ins.addUleb 8
    ins.addU8 DW_CFA_offset_hi or uint8(DwarfRaX64)   # RA at CFA + 1*(-8)
    ins.addUleb 1
  of dwA64:
    ins.addU8 DW_CFA_def_cfa; ins.addUleb uint64(DwarfSpA64); ins.addUleb 0

  var body: seq[byte] = @[]
  body.addU32 0                        # CIE_id: 0 marks a CIE in `.eh_frame`
  body.addU8 1                         # version
  body.add byte('z'); body.add byte('R'); body.add 0'u8   # augmentation "zR"
  body.addUleb 1                       # code alignment factor
  body.addSleb -8                      # data alignment factor
  body.addU8 uint8(if arch == dwX64: DwarfRaX64 else: DwarfRaA64)
  body.addUleb 1                       # augmentation data length
  body.addU8 DW_EH_PE_absptr           # 'R': how FDE addresses are encoded
  for x in ins: body.add x
  while (body.len + 4) mod 8 != 0: body.addU8 DW_CFA_nop
  result = @[]
  result.addU32 uint32(body.len)
  for x in body: result.add x

proc buildEhFrame*(procs: openArray[ProcUnwind]; arch: DwarfArch;
                   textBase: uint64; entryOffs: openArray[int]): seq[byte] =
  ## One CIE followed by one FDE per proc. `textBase` is the virtual address of
  ## code position 0, so `start`/`stop` become absolute addresses.
  ##
  ## `entryOffs` are the image's entry points — the ELF entry and, when nifasm
  ## synthesized a TLS/argv stub that tail-jumps to it, the real entry proc. Such
  ## a proc was not CALLED by anything: the kernel jumped to it, so there is no
  ## return address and the CIE's "RA at CFA-8" is a lie there. Its FDE declares
  ## the return address UNDEFINED, which is how an unwinder is told to stop
  ## rather than walk on into the argv block and report frames that are not
  ## frames (a libc's `_start` does exactly this).
  result = cieFor(arch)
  let cieAt = 0
  for p in procs:
    if p.stop <= p.start: continue     # a proc that emitted nothing
    var ins: seq[byte] = @[]
    var pos = p.start
    var isEntry = false
    for e in entryOffs:
      if e >= p.start and e < p.stop: isEntry = true
    if isEntry:
      ins.addU8 DW_CFA_undefined
      ins.addUleb uint64(if arch == dwX64: DwarfRaX64 else: DwarfRaA64)
    for s in p.steps:
      if s.at <= pos:
        # The layout passes can collapse code; a step that no longer advances
        # would emit `advance_loc 0`, which is legal but useless.
        discard
      else:
        advanceLoc(ins, s.at - pos)
        pos = s.at
      ins.addU8 DW_CFA_def_cfa_offset; ins.addUleb uint64(s.cfaOff)
      for sv in s.saves:
        let dw = dwarfNum(sv, arch)
        # `DW_CFA_offset(reg, N)` says: at CFA + N * dataAlign, i.e. CFA - 8N.
        let factored = uint64((-sv.cfaOff) div 8)
        if dw < 64:
          ins.addU8 DW_CFA_offset_hi or uint8(dw)
          ins.addUleb factored
        else:
          ins.addU8 0x05'u8            # DW_CFA_offset_extended
          ins.addUleb uint64(dw)
          ins.addUleb factored
    var body: seq[byte] = @[]
    body.addU64 textBase + uint64(p.start)          # initial_location (absptr)
    body.addU64 uint64(p.stop - p.start)            # address_range
    body.addUleb 0                                  # augmentation data length
    for x in ins: body.add x
    while (body.len + 8) mod 8 != 0: body.addU8 DW_CFA_nop
    let fdeAt = result.len
    result.addU32 uint32(body.len + 4)              # length (excl. itself)
    result.addU32 uint32(fdeAt + 4 - cieAt)         # CIE pointer: BACKWARD distance
    for x in body: result.add x
  result.addU32 0                                   # terminator

proc bodyCfaOff(p: ProcUnwind; arch: DwarfArch): int =
  ## The CFA offset that holds for the whole body: the state the LAST prologue
  ## step left behind, or — for a proc with no prologue at all (a leaf that
  ## needed no frame, a `{.naked.}` proc) — the ABI's entry state, which is what
  ## `pass2Proc` seeds `cfaOff` with.
  result = (if arch == dwA64: 0 else: 8)
  if p.steps.len > 0: result = int(p.steps[^1].cfaOff)

proc collectTraceProcs*(unwind: openArray[ProcUnwind]; arch: DwarfArch): seq[TraceProc] =
  ## The runtime trace table's rows, in ascending code order — which is what lets
  ## the runtime binary search. Emission order already is address order, but the
  ## table's contract says sorted, so it is sorted here rather than assumed by the
  ## reader.
  result = @[]
  for p in unwind:
    if p.stop <= p.start: continue
    result.add TraceProc(codeOff: p.start, codeLen: p.stop - p.start,
                         cfaOff: bodyCfaOff(p, arch), name: p.name)
  result.sort(proc (a, b: TraceProc): int = cmp(a.codeOff, b.codeOff))
