#
#           nifasm — the NIF assembler
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## What the assembler says when it refuses, and the two pieces of run state that
## only the message needs.
##
## `error` quits; it does not raise. arkham's asm-NIF carries no line info, so a
## bare type error names nothing you can act on — hence `gCurProc` (the mangled
## symbol pins the complaint to one module and one routine) and the rendered
## subtree.
##
## `lenient` is the `(lenient)` pragma of the proc being assembled, and it lives
## here because the routines that read it — the type-compatibility checks in
## `typecheck` — take no context. It is set once per proc, beside the mirror in
## `GenContext.lenient` that the instruction handlers read.

import nifcore, nifcoreparse   # `toString`: the offending subtree, rendered
import sem

var gCurProc = ""
var gLenient = false

proc setCurProc*(name: string) {.inline.} = gCurProc = name
  ## The proc being assembled, for `error`'s "in proc …" suffix.

proc setLenient*(on: bool) {.inline.} = gLenient = on
proc lenient*(): bool {.inline.} = gLenient
  ## The `(lenient)` pragma of the proc being assembled: ported code whose
  ## register discipline predates ours, checked less strictly by design.

proc nodeRepr*(n: Cursor): string =
  ## A compact rendering of the token at `n` for error messages (nifcore has no
  ## whole-subtree `toString` over a bare Cursor, and the diagnostic only needs
  ## the head). Negative tests match on the message text, not this.
  case n.kind
  of TagLit: "(" & tagName(n.tags, resolvedTagId(n))
  of Symbol, SymbolDef: "@" & n.symName
  of Ident: n.strVal
  of StrLit: "\"" & n.strVal & "\""
  of IntLit: $n.intVal
  of UIntLit: $n.uintVal
  of FloatLit: $n.floatVal
  of DotToken: "."
  else: $n.kind

proc infoStr*(n: Cursor): string =
  let li = n.rawLineInfo
  if li.isValid:
    result = n.lineInfoFile & "(" & $li.line & ", " & $li.col & ")"
  else:
    result = "???"

proc error*(msg: string; n: Cursor) =
  writeStackTrace()
  # `n` may be DRAINED — an error raised after an `into`-bounded scope has consumed
  # all its children (e.g. an `(at base index scratch)` disjointness check fires only
  # after the scratch is parsed) leaves the cursor past its last token, where `.kind`
  # / `rawLineInfo` would trip nifcore's `load` assert (`c.p != nil and c.rem > 0`).
  # Guard the position read so the diagnostic prints cleanly instead of crashing.
  let inProc = if gCurProc.len > 0: " in proc " & gCurProc else: ""
  if not cursorIsNil(n) and n.hasMore:
    # arkham's asm-NIF has no line info, so render the offending SUBTREE — the whole
    # instruction is what identifies it. Capped: a `(prepare …)` can be huge.
    var sub = toString(n, includeLineInfo = false)
    if sub.len > 400: sub = sub[0 ..< 400] & "…"
    quit "[Error] " & msg & " at " & infoStr(n) &
      " (kind=" & $n.kind & ", tag=" & nodeRepr(n) & ")" & inProc & "\n  " & sub
  else:
    quit "[Error] " & msg & inProc

proc typeError*(want, got: Type; n: Cursor) =
  error("Type mismatch: expected " & $want & ", got " & $got, n)
