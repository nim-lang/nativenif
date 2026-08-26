#
#           nifasm — the NIF assembler
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## Reading a value straight off a cursor, with the diagnostic that belongs to it.
##
## Every one of these is "the caller already knows what should be here" — a
## symbol, a string, an integer — so the interesting half is what they say when
## it is not, which is why they live beside `diagnostics` rather than in nifcore.

import nifcore
import diagnostics
import tags, decls               # the tag ids, and `tag` — the escape-aware read
import sem                       # asmWordBits: the target's own scalar width

proc getInt*(n: Cursor): int64 =
  if n.kind == IntLit:
    result = n.intVal
  else:
    error("Expected integer literal", n)

proc parseSlotAlign*(n: var Cursor): int =
  ## `n` is positioned at a `(s …)` stack-slot location. Read its optional
  ## `(align N)` child — the STACK-slot alignment, kept DISTINCT from the type's
  ## natural alignment (which drives struct-field layout) — and advance `n` PAST the
  ## whole `(s …)` node onto the slot's type. No annotation ⇒ the TARGET's slot
  ## granularity: 8 bytes on the 64-bit targets, 4 on Cortex-M. This is the one
  ## place stack-slot alignment enters nifasm; the codegen (arkham) decides the
  ## policy and emits the annotation.
  ##
  ## The hardcoded 8 here survived the word-size sweep and made every 32-bit stack
  ## slot 8 bytes wide, so two adjacent `(i 32)` slots came out 8 bytes apart —
  ## which nothing detects until something reads the pair as a unit.
  result = asmWordSize()
  n.into:                                  # enter (s); body is empty or one (align N)
    while n.hasMore:
      if n.kind == TagLit and n.tag == AlignTagId:
        n.into:
          result = int(getInt(n)); inc n   # the alignment integer
          while n.hasMore: skip n
      else:
        skip n                             # tolerate/ignore any other child

proc normScalarBits*(bits: int64): int =
  ## Leng encodes the architecture-width `int`/`uint`/`char` (and other
  ## native-word scalars) as a NON-POSITIVE bit count — `(i -1)` is the platform
  ## `int`. arkham resolves this to the word size (`slots.scalarSlot`: `bits <= 0`
  ## ⇒ 8 bytes); nifasm must agree or a `(i -1)` field is sized 0 and every later
  ## field's offset collapses (e.g. a ref payload's hidden header `(fld :r (i -1))`
  ## would put the real first field at offset 0, so `obj.field` reads the header).
  ## The width comes from the `(arch …)` pragma via `setAsmWordSize`, so a 32-bit
  ## target resolves it to 32 — see `asmWordBits`.
  if bits > 0: int(bits) else: asmWordBits()

# `symName` is nifcore's own. The NIF reader already completes the self-module
# trailing-dot compression (using each module's own suffix, set from its
# filename), so the interned string is module-correct as it stands and nothing
# here needs to wrap it.

proc getSym*(n: Cursor): string =
  case n.kind
  of Symbol:
    result = symName(n)
  else:
    error("Expected symbol", n)

proc getSymId*(n: Cursor): SymId =
  ## The interned identity of a `Symbol`/`SymbolDef` token — a key into the scope
  ## without materializing (and re-hashing) the qualified-name string. Valid across
  ## modules because every cursor interns into the one shared pool (`ctx.pool`).
  case n.kind
  of Symbol, SymbolDef:
    result = symId(n)
  else:
    error("Expected symbol", n)
    result = SymId(0)

proc getSymDef*(n: var Cursor): string =
  if n.kind != SymbolDef:
    error("Expected symbol definition", n)
  result = symName(n)
  skip n

proc getStr*(n: Cursor): string =
  if n.kind == StrLit:
    result = n.strVal
  else:
    error("Expected string literal", n)
