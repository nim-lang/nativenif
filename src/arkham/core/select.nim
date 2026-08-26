#
#           Arkham — native code generator for Leng
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#


## Recognising the select diamond: `if c: x = a else: x = b`.
##
## Both backends fold it into one branchless instruction — `csel` on AArch64,
## `cmov` on x86-64 — and the RECOGNITION is identical, so it lives here and
## each backend only supplies its own tag.

import std / [tables, sets, assertions, algorithm, strutils, os]
import symparser
import nifcore, nifcdecl
import asmslots, machinedesc, analyser, planer, programs, abi
import "../arm/machine_m"
import layout, asmbuf, typenav, regbind, context
import diag, asmcommon, typeutil, constdata, mirrors


# ── select-diamond recognition (shared by a64 `csel` & x64 `cmov`) ────────────

type
  SelectDiamond* = object
    ## A recognised `(if (elif COND (asgn DST A)) (else (asgn DST B)))` where COND is
    ## an integer relation, DST a register-homed scalar, and A/B are side-effect-free
    ## simple values — lowered branchlessly (a64 `csel`, x64 `cmov`).
    ek*: LengExpr                 # relation kind: EqC / NeqC / LtC / LeC
    a*, b*: Cursor                # relation operands
    dst*: Location                # the shared register-homed destination
    thenAsgn*, elseAsgn*: Cursor  # the two `(asgn …)` nodes (for their positions)
    thenRhs*, elseRhs*: Cursor    # the assigned values (A, B)

proc simpleSelectValue(g: var CodeGen; rhs: Cursor): bool =
  ## A side-effect-free scalar RHS that materialises with plain `mov`/`ldr`/`lea`
  ## only — never touching the condition flags, so it may sit between the compare and
  ## the `csel`/`cmov`: an integer immediate, or a register-/stack-homed local.
  ## Peels `(suf …)` / `(par …)` / identity `(cast …)` / `(conv …)` wrappers that
  ## xelim / typed lowering leave around literals and symbols (e.g. `max(16, alignment)`
  ## after hexer), matching the peels used elsewhere in this module.
  var v = rhs
  while v.kind == TagLit and v.exprKind in {SufC, ParC, CastC, ConvC}:
    if v.exprKind in {CastC, ConvC}: (inc v; skip v)   # past tag + target type
    else: inc v                                        # descend to the wrapped value
  case v.kind
  of IntLit, UIntLit, CharLit: true
  of Symbol: g.plan.locationOfSym(symName(v), cursorToPosition(g.buf[], v)).kind in {InReg, NamedStack}
  else: false

proc selectAsgnDstRhs(asgn: Cursor; dstName: var string; rhs: var Cursor): bool =
  ## `(asgn DST RHS)` with a symbol DST → its name and the RHS cursor. False for a
  ## complex (memory) lvalue. `sub` reads the children without a leave obligation.
  var a = sub(asgn)
  if a.kind != Symbol: return false
  dstName = symName(a); skip a
  if not a.hasMore: return false
  rhs = a
  return true

proc singleAsgnOf(stmt: Cursor; asgn: var Cursor): bool =
  ## The lone `(asgn …)` a select-diamond arm carries: the statement itself, or the
  ## single child of nested `(stmts …)` wrappers. Hexer/xelim often wrap an arm as
  ## `(stmts (stmts (stmts (asgn …))))`; peel until one assignment remains. False for
  ## anything else (zero/multiple statements, a non-assignment) — those keep the
  ## branch lowering.
  var s = stmt
  while s.stmtKind == StmtsS:
    var inner = sub(s)
    if not inner.hasMore: return false
    let first = inner; skip inner
    if inner.hasMore: return false          # more than one statement in the arm
    s = first
  if s.stmtKind == AsgnS:
    asgn = s; return true
  return false

proc matchSelectDiamond*(g: var CodeGen; c: Cursor; sd: var SelectDiamond): bool =
  ## Recognise `(if (elif COND (asgn DST A)) (else (asgn DST B)))` — exactly one
  ## elif and one else, each arm a single assignment to the SAME register-homed
  ## scalar DST from a side-effect-free simple value, with COND a plain integer
  ## relation (eq/ne/lt/le). Fills `sd` and returns true; false (→ the caller's
  ## branch lowering) for anything that does not fit. Arch-independent: the a64
  ## backend lowers a match to `csel`, the x64 backend to `cmov`.
  var condC, thenAsgn, elseAsgn: Cursor
  var haveElif, haveElse = false
  var ok = true
  var cc = c
  cc.into:
    while cc.hasMore:
      case cc.substructureKind
      of ElifU:
        if haveElif or haveElse: ok = false
        var bc = sub(cc)                       # (elif COND ARM) — read only
        condC = bc; skip bc
        if not bc.hasMore: ok = false
        else:
          thenAsgn = bc; skip bc
          if bc.hasMore: ok = false            # more than one statement in the arm
        haveElif = true
      of ElseU:
        if not haveElif or haveElse: ok = false
        var bc = sub(cc)                       # (else ARM)
        if not bc.hasMore: ok = false
        else:
          elseAsgn = bc; skip bc
          if bc.hasMore: ok = false
        haveElse = true
      else: ok = false
      skip cc
  if not (ok and haveElif and haveElse): return false
  var thenBody, elseBody: Cursor
  if not singleAsgnOf(thenAsgn, thenBody): return false
  if not singleAsgnOf(elseAsgn, elseBody): return false
  if condC.kind != TagLit or condC.exprKind notin {EqC, NeqC, LtC, LeC}: return false
  var aC, bC: Cursor
  block:
    var pc = sub(condC)
    aC = pc; skip pc
    bC = pc
  if g.isFloatExpr(aC): return false
  var thenDst, elseDst: string
  var thenRhs, elseRhs: Cursor
  if not selectAsgnDstRhs(thenBody, thenDst, thenRhs): return false
  if not selectAsgnDstRhs(elseBody, elseDst, elseRhs): return false
  if thenDst != elseDst: return false
  let dst = g.plan.homeOfSym(thenDst)
  if dst.kind != InReg: return false
  if not g.simpleSelectValue(thenRhs) or not g.simpleSelectValue(elseRhs): return false
  sd = SelectDiamond(ek: condC.exprKind, a: aC, b: bC, dst: dst,
                     thenAsgn: thenBody, elseAsgn: elseBody,
                     thenRhs: thenRhs, elseRhs: elseRhs)
  return true

proc selectStagingSlot*(g: var CodeGen; sd: SelectDiamond): AsmSlot =
  ## The slot for the register that stages the THEN value. It receives a COPY of DST,
  ## so it must be bound with DST's *asm* type — which is simply DST's own slot: both
  ## backends' `emRegLocalVar` declares a register-homed local with its OWN type
  ## (`(u 8)` stays `(u 8)`). This used to answer a flat `(i 64)` for every
  ## non-pointer, matching the older declaration rule; once that rule changed, an
  ## `enum`/`uint8` DST declared `(u 8)` made the `csel DST, staging, DST` against an
  ## `(i 64)` staging register a type error (`posixToErrorCode`, whose `ErrorCode`
  ## result the select-diamond lowering reaches).
  sd.dst.typ