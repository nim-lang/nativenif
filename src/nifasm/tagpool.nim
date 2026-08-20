## The seeded `nifcore` tag pool for asm-NIF, shared by the assembler and by
## arkham's builder (`asmbuf`).
##
## asm-NIF's vocabulary does not fit NIF's 9-bit tag field: 282 of its spellings
## are machine mnemonics that only ONE target can ever use, and every further
## target (Cortex-M, RISC-V) wants a few hundred more. The pool is therefore not
## capped at 511 — ids past that are spelled through the `other` escape tag (see
## `nifcore.TagPool.escapeTag`), which costs one extra token and nothing else.
## `gen_instructions` numbers the per-target mnemonics LAST so the overflow
## falls on them rather than on a register or a structural tag.
##
## The escape is invisible on both sides of the buffer: `openTag` folds it and
## the serializers unfold it, so the NIF *text* is unchanged and so is the
## binary token format. It is visible only to a cursor walking the buffer, in
## exactly two ways:
##
## 1. the id is not `cursorTagId` — decode with `nifcore.resolvedTagId`, which
##    is what this module's `tag` accessor in `assembler.nim` uses, so
##    `tagTo…(n.tag)` keeps working;
## 2. the id is a CHILD, so operands start one token later — `genInstX64` /
##    `genInstA64` step over it once before dispatching, and the handful of
##    places that consume a whole node use `intoOperands`.

import nifcore
import tags

const
  OtherTag* = TagId(ord(OtherTagId))
    ## The escape header. `(other <id> …)`; never spelled in text.

proc createAsmTagPool*(): TagPool =
  ## A `nifcore` tag pool seeded so each asm-NIF tag's `TagId` equals its
  ## `TagEnum` ordinal (the same scheme arkham uses for Leng in
  ## `arkham/lengdecl.createLengTagPool`), so `resolvedTagId` decodes by ordinal
  ## via `cast[TagEnum](…)`. Shared across the main module and every
  ## lazily-parsed foreign decl so ordinals line up.
  ##
  ## `AnonTagId` is the empty spelling — the tree whose head is a SymbolDef,
  ## `(result (:ret.0 (rax) (i 64)))`. It is seeded like any other tag, and that
  ## is the point: a tag the PARSER has to intern takes whatever id is free, and
  ## past 511 that id no longer fits a token and silently takes the escape.
  ## Seeding the whole vocabulary is what keeps the escape a decision this file
  ## makes rather than one the input makes.
  result = newTagPool()
  for e in TagEnum:
    if e == InvalidTagId: continue
    let id = result.registerTag(TagData[e][0])
    assert uint32(id) == uint32(TagData[e][1]),
      "nifasm tag pool misalignment for " & TagData[e][0]
  result.escapeTag = OtherTag

proc enterNode*(n: var Cursor) {.inline.} =
  ## Step from a node head onto its first child, past the id of a tag that did
  ## not fit the 9-bit field. Use it instead of a bare `inc n` wherever the node
  ## is not one of the tags this reader knows by name — a tag interned while
  ## PARSING (asm-NIF's anonymous tree head `(:ret.0 …)` is one) lands wherever
  ## the pool's next free id happens to be, and past 511 that means escaped.
  let escaped = isEscapedTag(n)
  inc n
  if escaped: inc n

template intoOperands*(n: var Cursor; body: untyped) =
  ## `into` over an instruction node, landing `body` on operand 0 whether or not
  ## the mnemonic needed the escape. Use it where code consumes the WHOLE node
  ## rather than walking `n` forward operand by operand — `n.into` alone would
  ## hand `body` the escaped id as if it were the first operand.
  let escapedHead = isEscapedTag(n)
  n.into:
    if escapedHead: inc n
    body
