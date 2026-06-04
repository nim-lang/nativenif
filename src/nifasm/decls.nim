#
#           nifasm — Native NIF Assembler
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution, for
#    details about the copyright.
#

## Structured extraction helpers for asm-NIF declarative constructs (`proc`,
## `gvar`/`tvar`/`rodata`, `type`, `params`/`result`/`clobber`/`param`, object
## and union fields). Modeled on nimony's `decls.nim`: each helper destructures
## a cursor positioned at a construct into named sub-cursors that the caller
## then reads/validates.
##
## The helpers are deliberately written in the *portable* `into`/`skip`/
## `hasMore` idiom — they never compare against an explicit `ParRi` token. This
## is the bridge that lets the very same code run on the legacy ParRi-based
## cursor API (`nifcursors`) and the new `nifcore` API, where tree nesting is
## carried by a tag's body-token count and there is no `ParRi` sentinel at all.

import nifcore
import tags, model, tagconv

template rawTag*(c: Cursor): TagEnum =
  ## The cursor's tag as a `TagEnum` (only meaningful at a `TagLit`).
  cast[TagEnum](uint32(c.cursorTagId))

template declTag*(c: Cursor): NifasmDecl =
  ## The cursor's tag decoded as a `NifasmDecl`, or `NoDecl` if it is not one
  ## (or the cursor is not at a tag).
  (if c.kind == TagLit: tagToNifasmDecl(cast[TagEnum](uint32(c.cursorTagId))) else: NoDecl)

template atTag*(c: Cursor; t: TagEnum): bool =
  ## True when `c` is at a `TagLit` whose tag equals `t`.
  c.kind == TagLit and cast[TagEnum](uint32(c.cursorTagId)) == t

type
  RoutineSig* = object
    ## The optional `(params …)`/`(result …)`/`(clobber …)` sections of a
    ## `proc`/`proctype`/`proc`-decl, captured as cursors at each section's
    ## `ParLe`. A `has*` flag is false (and the matching cursor nil) when that
    ## section is absent.
    params*: Cursor
    res*: Cursor
    clobber*: Cursor
    hasParams*, hasResult*, hasClobber*: bool

proc takeSig*(c: var Cursor): RoutineSig =
  ## `c` is positioned at the first optional section of a routine signature
  ## (i.e. just past the routine's name, or just past the `proctype`/`proc`
  ## type tag). Captures any leading `(params)`/`(result)`/`(clobber)` sections
  ## in order and leaves `c` at the first child that is not one of them — the
  ## body `(stmts …)`, a trailing type qualifier, or the end of the node.
  result = RoutineSig()
  while c.hasMore and c.kind == TagLit:
    case declTag(c)
    of ParamsD:
      result.params = c; result.hasParams = true; skip c
    of ResultD:
      result.res = c; result.hasResult = true; skip c
    of ClobberD:
      result.clobber = c; result.hasClobber = true; skip c
    else:
      break

type
  Routine* = object
    ## A whole `(proc :Name (params)? (result)? (clobber)? Body?)` declaration.
    name*: Cursor      ## the `SymbolDef`
    sig*: RoutineSig
    body*: Cursor      ## the body `(stmts …)`, nil if absent (e.g. a foreign
                       ## proc decl carries only the signature)
    hasBody*: bool

proc takeRoutine*(c: var Cursor): Routine =
  ## `c` is positioned at a `(proc …)`/`(proctype …)` node. Captures the name,
  ## the signature sections and the body, advancing `c` past the whole node.
  result = Routine()
  into c:
    result.name = c
    skip c
    result.sig = takeSig(c)
    if c.hasMore:
      result.body = c
      result.hasBody = true
      skip c

type
  AsmParam* = object
    ## One `(param :Name Location Type)` / `(ret :Name Location Type)` entry.
    name*: Cursor      ## the `SymbolDef`
    location*: Cursor  ## the location tag node: `(<reg>)` or `(s)`
    typ*: Cursor       ## the type slot

proc takeParam*(c: var Cursor): AsmParam =
  ## `c` at a `(param …)`/`(ret …)` node (already known to be one). Captures the
  ## three slots and advances `c` past the node.
  result = AsmParam()
  into c:
    result.name = c
    skip c
    result.location = c
    skip c
    result.typ = c
    skip c

iterator params*(c: Cursor): Cursor =
  ## `c` at a `(params …)` (or `(result …)`) node. Yields a cursor at each
  ## child `(param …)`/`(ret …)` entry. Does not mutate `c`.
  var c = c
  into c:
    while c.hasMore:
      yield c
      skip c

type
  Local* = object
    ## A `(gvar/tvar/rodata/var :Name Type Value?)` declaration.
    kind*: NifasmDecl
    name*: Cursor      ## the `SymbolDef`
    typ*: Cursor       ## the type slot (nil for `rodata`, which has no type)
    val*: Cursor       ## the initializer, nil if absent
    hasVal*: bool

proc takeLocal*(c: var Cursor): Local =
  ## `c` at a `(gvar/tvar/var …)` node. Captures name, type and optional value,
  ## advancing `c` past the node.
  result = Local(kind: declTag(c))
  into c:
    result.name = c
    skip c
    if c.hasMore:
      result.typ = c
      skip c
    if c.hasMore:
      result.val = c
      result.hasVal = true
      skip c

type
  TypeDecl* = object
    ## A `(type :Name Body)` declaration.
    name*: Cursor   ## the `SymbolDef`
    body*: Cursor   ## the type body (`(object …)`, `(union …)` or a plain type)

proc takeTypeDecl*(c: var Cursor): TypeDecl =
  ## `c` at a `(type …)` node. Captures the name and body, advancing `c` past
  ## the node.
  result = TypeDecl()
  into c:
    result.name = c
    skip c
    result.body = c
    skip c

iterator fields*(c: Cursor): Cursor =
  ## `c` at an `(object …)`/`(union …)` node. Yields a cursor at each `(fld …)`
  ## child, tolerating (and skipping) a leading non-`fld` slot — the optional
  ## NIFC inheritance/base type carried only by `object`. Does not mutate `c`.
  var c = c
  into c:
    # `(object [Empty | Type-base] FieldDecl*)` — skip a leading non-field slot.
    if c.hasMore and not atTag(c, FldTagId):
      skip c
    while c.hasMore:
      yield c
      skip c

type
  Field* = object
    ## One `(fld :Name FieldPragmas? Type)` entry.
    name*: Cursor   ## the `SymbolDef`
    typ*: Cursor    ## the type slot (after tolerating an optional pragmas slot)

proc takeField*(c: var Cursor; atTypeStart: proc (c: Cursor): bool {.nimcall.}): Field =
  ## `c` at a `(fld …)` node. Captures the name and type, tolerating the
  ## optional NIFC `FieldPragmas` slot before the type (detected via the
  ## caller-supplied `atTypeStart`, which knows the type grammar). Advances `c`
  ## past the node.
  result = Field()
  into c:
    result.name = c
    skip c
    if not atTypeStart(c): skip c   # tolerate FieldPragmas
    result.typ = c
    skip c
