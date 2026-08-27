#
#           Arkham — native code generator for Leng
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#


## `.assembler` bodies: the half that is the same on every target.
##
## What a pragma says a local lives in, what an operand node names, which
## intrinsic row an instruction is — all decided here. The transliteration into
## actual instructions is per-target and lives beside each selector.

import std / [tables, sets, strutils]

import nifcore, nifcdecl
import machinedesc, programs
import "../risc/machine_m"
import context
import diag


# ── `.assembler` bodies: the target-neutral half ────────────────────────────
# doc/intrinsics.md §8. What a location pragma SAYS, what counts as an ATOM, and
# which row a call names are the same three questions on every target; only the
# register vocabulary and the opcodes differ. Both back ends read the answers
# from here and add their own `asmPinReg`, so a rule stated once cannot drift
# into two subtly different subsets of the same source language.

type
  AsmDeclKind* = enum
    aslNone,       ## no location pragma at all
    aslReg,        ## `{.register: "rax".}`
    aslStack       ## `{.stack.}`

  AsmDeclSpec* = object
    ## A param's or local's DECLARED location, with the register name still
    ## UNRESOLVED — resolving it is exactly where the targets differ. The pragma
    ## node travels along so a rejection points at the annotation the user wrote
    ## rather than at the declaration that carries it.
    kind*: AsmDeclKind
    name*: string
    at*: Cursor

proc asmDeclSpec*(prag: Cursor): AsmDeclSpec =
  ## Read `(pragmas (register "…"))` / `(pragmas (stack))` off a param or local.
  result = AsmDeclSpec(kind: aslNone, name: "", at: prag)
  if prag.substructureKind != PragmasU: return
  var p = prag
  p.into:
    while p.hasMore:
      case p.pragmaKind
      of RegisterP:
        let at = p
        var nm = ""
        p.into:
          if p.hasMore and p.kind == StrLit: (nm = strVal(p); inc p)
          while p.hasMore: skip p
        result = AsmDeclSpec(kind: aslReg, name: nm, at: at)
      of StackP:
        result = AsmDeclSpec(kind: aslStack, name: "", at: p)
        skip p
      else: skip p

proc isResultName*(nm: string): bool {.inline.} =
  ## Nimony names a routine's implicit result `result.<n>[.<module>]`. It is the one
  ## local a user cannot annotate — `result` is not a declaration they write — so
  ## `.assembler` pins it to the ABI return register instead of demanding a pragma.
  nm.startsWith("result.")

proc asmAtom*(c: Cursor): Cursor =
  ## Peel the type-only wrappers the front end puts around a literal: `result = 100`
  ## in a `uint64` context arrives as `(conv (u 64) 100)`, and a literal that
  ## carried a type suffix in the source (`0xAB'i32`) as `(suf 171 "i32")`. A
  ## conversion of a CONSTANT is a fact about the constant — the assembler encodes
  ## the immediate at the operand's width and no instruction exists to emit — so
  ## folding it is what "one-to-one" means here. A `conv` of a *value* is a real
  ## sign/zero extension and is left alone, so it still reaches its back end's
  ## rejection.
  result = c
  while result.kind == TagLit and result.exprKind in {SufC, ParC}:
    # `(suf value "type")` / `(par value)`: the wrapped value is the first child
    # and the wrapper says nothing an instruction could encode.
    inc result
  while result.kind == TagLit and result.exprKind in {ConvC, CastC}:
    var inner = result
    var got = result
    var count = 0
    inner.into:
      skip inner                                 # the target type
      while inner.hasMore:
        if count == 0: got = inner
        inc count
        skip inner
    if count != 1: return
    # Peel into a temporary and commit only if a LITERAL came out: a `conv` whose
    # operand is a value is a real sign/zero extension, and returning its inner
    # node would drop the extension instead of reaching the rejection.
    var peeled = got
    while peeled.kind == TagLit and peeled.exprKind in {SufC, ParC}: inc peeled
    if peeled.kind notin {IntLit, UIntLit, CharLit}: return
    result = peeled
    return

proc asmNoteInfo*(g: var CodeGen; c: Cursor) {.inline.} =
  ## Remember the innermost node that carried line info, so a rejection deeper in
  ## (NIF line info is sparse) still points at the right statement.
  let li = lengInfo(c)
  if li.len > 0: g.asmInfo = li

proc isAsmStackSym*(g: CodeGen; c: Cursor): bool {.inline.} =
  c.kind == Symbol and symName(c) in g.asmStack

proc asmRegOf*(g: var CodeGen; c: Cursor): Reg =
  ## The register an operand names. `.assembler` operands must be ATOMS, so this is
  ## a table lookup and nothing else — no evaluation, no materialization.
  if c.kind != Symbol:
    lengError c, "an `.assembler` operand must be a variable or a literal, not " &
              "a computed expression", g.asmInfo
  let nm = symName(c)
  if nm in g.asmStack:
    lengError c, "`" & userName(nm) & "` lives on the stack; this operand needs a register",
              g.asmInfo
  if not g.asmReg.hasKey(nm):
    lengError c, "`" & userName(nm) & "` has no declared location — every local in an " &
              "`.assembler` proc needs `{.register: \"…\".}` or `{.stack.}`", g.asmInfo
  result = g.asmReg[nm]

proc instrOpAt*(g: var CodeGen; c: Cursor): IntrinsicOp =
  ## The row an `(instr SYM …)` node names, or `NoIntrinsicOp` if `c` is not one.
  result = NoIntrinsicOp
  if c.kind != TagLit or c.exprKind != InstrC: return
  var fc = c
  var sym = ""
  fc.into:
    sym = symName(fc); skip fc
    while fc.hasMore: skip fc
  result = instrTargetOf(g.prog, sym).op