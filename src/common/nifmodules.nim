#
#           Shared foreign-module loader for the nifcore backends
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## Lazy, on-demand loader for foreign NIF modules over the **nifcore** API —
## the single mechanism shared by arkham (codegen) and nifasm (assembler/linker)
## so the whole pipeline resolves cross-module symbols the same way.
##
## Every NIF module carries an embedded `.indexat`/`.index` (hexer output;
## `nimony/tools/reindex.nim` ensures even hand-written fixtures have one). We
## keep the module's `Reader` open and parse just the *one* requested
## declaration by `jumpTo`-ing its indexed byte offset — O(1) per symbol, so a
## 400 KB module is never parsed whole. The per-decl buffers are owned by the
## `ForeignModule` so the cursors into them stay valid for its lifetime.

import std / [tables]
import nifcore, nifcoreparse
import "../../../nimony/src/lib" / [nifreader, stringviews]

type
  ForeignModule* = ref object
    r*: Reader                          ## open reader (lazy per-symbol jumps)
    index*: Table[string, int]          ## symbol → absolute byte offset
    decls*: Table[string, Cursor]       ## parsed-decl cache
    declBufs*: seq[TokenBuf]            ## per-decl buffers, kept alive
    hasEmbeddedIndex*: bool             ## false → the file carried no `.indexat`

proc readEmbeddedIndex*(r: var Reader): Table[string, int] =
  ## Read the embedded `(.index (h sym Δoff) (x sym Δoff) …)` section located by
  ## the `.indexat` directive, returning `symbol → absolute byte offset`. Offsets
  ## are stored delta-encoded (cumulative); `h`=hidden, `x`=exported (we keep
  ## both). Mirrors `nifindexes.readEmbeddedIndex`, but over the nifcore reader.
  result = initTable[string, int]()
  let indexPos = indexStartsAt(r)
  if indexPos <= 0: return
  r.jumpTo(indexPos)
  var prev = 0
  var t = default(ExpandedToken)
  next(r, t)                                  # `(.index`
  if not (t.tk == ParLe and t.data == ".index"): return
  next(r, t)
  while t.tk != EofToken and t.tk != ParRi:
    if t.tk == ParLe:                         # entry: `(h sym Δoff)` / `(x sym Δoff)`
      next(r, t)                              # the symbol
      var key = ""
      if t.tk == Symbol: key = decodeStr(r, t)
      next(r, t)                              # the (delta) offset
      if t.tk == IntLit:
        let off = int(decodeInt t) + prev
        if key.len > 0: result[key] = off
        prev = off
      next(r, t)                              # closing `)`
      if t.tk == ParRi: next(r, t)
    else:
      next(r, t)

proc openForeignModule*(path: string): ForeignModule =
  ## Open a module file: read its directives, locate the embedded `.indexat`
  ## index, and keep the reader open for lazy per-symbol jumps. The returned
  ## module's `hasEmbeddedIndex` is false when the file carried no index — the
  ## caller decides how to report that (arkham/nifasm phrase the error).
  result = ForeignModule(r: nifreader.open(path),
                         index: initTable[string, int](),
                         decls: initTable[string, Cursor]())
  if indexStartsAt(result.r) > 0:
    result.hasEmbeddedIndex = true
    result.index = readEmbeddedIndex(result.r)

proc hasDecl*(m: ForeignModule; name: string): bool =
  m.decls.hasKey(name) or m.index.hasKey(name)

proc getDecl*(m: ForeignModule; name: string; tags: TagPool): Cursor =
  ## The declaration cursor for `name` (precondition: `hasDecl`). `jumpTo`s the
  ## symbol's byte offset and parses just that one tree into its own buffer
  ## (kept alive in `declBufs`). Cached.
  if m.decls.hasKey(name): return m.decls[name]
  m.r.jumpTo(m.index[name])
  var buf = createTokenBuf(64, nil, tags)
  parse(m.r, buf)                             # exactly one balanced decl tree
  # Take the cursor on the LOCAL buffer *before* moving it into `declBufs`
  # (the nifc/nimony pattern, see nifmodules.getDeclOrNil): `beginRead` installs
  # the buffer's ref-counted cursor owner, which then travels with the buffer
  # when `declBufs` later grows and relocates its elements. Doing `beginRead` on
  # the already-stored seq element instead corrupts the heap once a second decl
  # forces the seq to reallocate.
  result = beginRead(buf)
  m.declBufs.add ensureMove(buf)
  m.decls[name] = result
