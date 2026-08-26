#
#           nifasm — the NIF assembler
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## asm-NIF register tags -> AVR registers and register pairs.
##
## There are two register vocabularies here rather than one, and the split is the
## whole design: `(r0)`..`(r31)` name the machine's real 8-bit registers, which
## is what every ALU instruction operates on, and `(rp0)`..`(rp30)` name the
## even-aligned PAIRS, which is what the code generator allocates and what
## `movw`/`adiw`/`sbiw` and the three pointer registers take.
##
## Only the forms that genuinely ARE one instruction on a pair accept a pair tag.
## A 16-bit add is two `(add)`/`(adc)` nodes on the halves, because that is two
## instructions and the assembler does not invent the second one.
##
## As on Cortex-M, an AVR register tag is also a valid x86-64 one — `(r0)` is an
## alias for rax there — so `(arch …)` is what decides which file a spelling
## names, not the tag.

import nifcore
import "../core" / [tags, model, tagconv, decls, diagnostics]
import encoder as avr

proc rawTagIsAvrPair*(t: TagEnum): bool {.inline.} =
  ## `(rp0)`..`(rp30)`. Contiguous because the generator numbered them in one run
  ## and every one of them is AVR-only, so nothing can be interleaved.
  t >= Rp0TagId and t <= Rp30TagId

proc rawTagIsAvrGpr*(t: TagEnum): bool {.inline.} =
  ## An 8-bit register. `rawTagIsAvrReg` covers the pairs as well, so every site
  ## that means "one register" has to say so — otherwise `(rp24)` binds a
  ## variable to r24 and silently leaves r25 free for something else.
  rawTagIsAvrReg(t) and not rawTagIsAvrPair(t)

proc tagToRegisterAvr*(t: TagEnum; n: Cursor): avr.Register =
  if rawTagIsAvrPair(t):
    error("Expected an 8-bit register, got a register pair", n)
    return avr.R0
  let regTag = tagToAvrReg(t)
  result =
    case regTag
    of R0AR: avr.R0
    of R1AR: avr.R1
    of R2AR: avr.R2
    of R3AR: avr.R3
    of R4AR: avr.R4
    of R5AR: avr.R5
    of R6AR: avr.R6
    of R7AR: avr.R7
    of R8AR: avr.R8
    of R9AR: avr.R9
    of R10AR: avr.R10
    of R11AR: avr.R11
    of R12AR: avr.R12
    of R13AR: avr.R13
    of R14AR: avr.R14
    of R15AR: avr.R15
    of R16AR: avr.R16
    of R17AR: avr.R17
    of R18AR: avr.R18
    of R19AR: avr.R19
    of R20AR: avr.R20
    of R21AR: avr.R21
    of R22AR: avr.R22
    of R23AR: avr.R23
    of R24AR: avr.R24
    of R25AR: avr.R25
    of R26AR: avr.R26
    of R27AR: avr.R27
    of R28AR: avr.R28
    of R29AR: avr.R29
    of R30AR: avr.R30
    of R31AR: avr.R31
    else:
      error("Expected an AVR register", n)
      avr.R0

proc tagToPairAvr*(t: TagEnum; n: Cursor): avr.Pair =
  if not rawTagIsAvrPair(t):
    error("Expected a register pair `(rp0)`..`(rp30)`", n)
    return avr.P0
  avr.Pair(2 * (int(t) - int(Rp0TagId)))

# `skip n`, not `inc n`, at every one of these — and that is not a style choice.
# AVR's own register tags are numbered past the 511 that fit NIF's 9-bit tag
# field, so `(rp24)` is spelled through the escape and carries its real id in a
# leading `IntLit` child. `inc` would land ON that child; `skip` passes the whole
# node whichever shape it has. The other targets never met this because their
# register spellings all predate the overflow.

proc parseRegisterAvr*(n: var Cursor): avr.Register =
  if n.kind != TagLit or not rawTagIsAvrGpr(n.tag):
    error("Expected an AVR register `(r0)`..`(r31)`", n)
  result = tagToRegisterAvr(n.tag, n)
  skip n

proc parsePairAvr*(n: var Cursor): avr.Pair =
  if n.kind != TagLit or not rawTagIsAvrPair(n.tag):
    error("Expected a register pair `(rp0)`..`(rp30)`", n)
  result = tagToPairAvr(n.tag, n)
  skip n

proc lowOf*(p: avr.Pair): avr.Register {.inline.} = avr.Register(ord(p))
proc highOf*(p: avr.Pair): avr.Register {.inline.} = avr.Register(ord(p) + 1)

proc pairOf*(r: avr.Register): avr.Pair {.inline.} =
  ## The pair a register is a half of. Total, because every register is: the
  ## question a caller actually has is whether it is the LOW half, which
  ## `lowOf(pairOf(r)) == r` answers.
  avr.Pair(ord(r) and not 1)

proc ptrRegOf*(p: avr.Pair; n: Cursor): avr.PtrReg =
  ## X, Y or Z — the only three pairs that can address memory. Anything else is
  ## an error rather than a load through a scratch: putting an address into a
  ## pointer register is code generation, and this is the assembler.
  case p
  of avr.X: avr.PX
  of avr.Y: avr.PY
  of avr.Z: avr.PZ
  else:
    error("`(rp" & $ord(p) & ")` cannot address memory: only X (`rp26`), " &
          "Y (`rp28`) and Z (`rp30`) can", n)
    avr.PZ

proc regName*(r: avr.Register): string = "r" & $ord(r)
proc pairName*(p: avr.Pair): string =
  "rp" & $ord(p) & " (r" & $(ord(p) + 1) & ":r" & $ord(p) & ")"
