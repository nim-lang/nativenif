#
#           Arkham — native code generator for Leng
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#


## What arkham says when it refuses an `.assembler` body.
##
## Most of arkham’s internal checks are `raiseAssert`s — they can only fire on a
## compiler bug, and a stack trace is the useful output. An `.assembler` body is
## different: arkham is the ONLY checker of that source-level subset, so its
## rejections are ordinary user errors and have to read like one.


import symparser
import nifcore



# ── user-facing diagnostics ─────────────────────────────────────────────────
# Most of arkham's internal consistency checks are `raiseAssert`s: they can only
# fire on a compiler bug, so a stack trace is the useful output. An `.assembler`
# body is different — arkham is the ONLY checker of that source-level subset (see
# `doc/intrinsics.md` §8), so its rejections are ordinary user errors and must
# read like one. NIF carries the original file/line/col on the very node that is
# wrong, which is why delegating the checking here costs no diagnostic quality.

proc userName*(sym: string): string =
  ## `r.0.mymod` → `r`. A NIF symbol is `<name>.<disambiguator>[.<module>]`; both
  ## suffixes belong to the front end, so neither may appear in a message a human
  ## reads — they would name something the user never wrote.
  result = splitSymName(sym).name             # drops the module suffix
  var i = result.len - 1
  while i > 0 and result[i] in {'0' .. '9'}: dec i
  if i > 0 and i < result.len - 1 and result[i] == '.': result.setLen i

proc lengInfo*(c: Cursor): string =
  ## `file(line, col)` for the Leng node `c`, or "" when it carries no line info
  ## (NIF line info is sparse: only nodes the front end stamped have it).
  let li = rawLineInfo(c)
  if not li.file.isValid: return ""
  result = lineInfoFile(c) & "(" & $li.line & ", " & $li.col & ")"

proc lengError*(c: Cursor; msg: string; fallback = "") {.noreturn.} =
  ## Report a user error against the Leng node `c` and stop. `fallback` is a
  ## previously-seen `lengInfo` used when `c` itself is uninformative, so a
  ## rejection always points at least at the enclosing statement.
  var where = lengInfo(c)
  if where.len == 0: where = fallback
  if where.len == 0: where = "arkham"
  quit where & " Error: " & msg, QuitFailure