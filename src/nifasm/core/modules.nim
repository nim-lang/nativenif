#
#           nifasm — the NIF assembler
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## The module system's bookkeeping: which foreign modules are open, which
## dynamic libraries are imported, which symbols still owe a body, and which
## generic instantiation is the canonical one.
##
## A foreign module is opened LAZILY — only its embedded NIF `.index` is read up
## front, and a declaration is parsed when a name reaches it. The parsing itself
## is `typesem.resolveForeignSym`’s job; what lives here is everything around it
## that needs no type knowledge at all.

import std / [tables, sets, os, strutils]
import nifcore, nifmodules
import "../../../../nimony/src/lib" / symparser
import context, diagnostics, cursors

const
  WindowsKernelDll* = "kernel32.dll"
    ## The implicit import library of a Windows image — the one arkham binds against.

proc extractDedupKey*(s: string): string =
  ## The COMDAT key of a generic instantiation: `foo.0.Ihash.moduleSuffix` ->
  ## `foo.0.Ihash`. Every module that needs an instantiation emits its own copy,
  ## so the copies must collapse onto one definition — that is what this key is
  ## for. `""` means "not a duplicate of anything", and the symbol keeps its own
  ## definition.
  ##
  ## The key is the name minus its module suffix, and dropping the module is only
  ## sound when what remains is GLOBALLY unique. That is a property of the NAME
  ## SHAPE, and nif-spec.md owns it: a global symbol is `<ident>.<disamb>.<mod>`
  ## or `<ident>.<disamb>.<key>.<mod>`, "where `key` usually is the result from a
  ## generic instantiation". The key slot answers WHICH instantiation of
  ## `<ident>.<disamb>` this is, and because every importing module derives the
  ## same key independently, `<ident>.<disamb>.<key>` means the same thing in all
  ## of them.
  ##
  ## Which names occupy that slot is therefore NOT a question this assembler gets
  ## to answer on its own — `symparser.isInstantiation` is the toolchain's single
  ## answer, and it is nimony's too (DCE's `resolveSymbolConflicts` and
  ## `lengcgen`'s content-hashed `strlit.0.I<hash>.<mod>` key on the same rule).
  ## This module used to hand-roll a third copy of it, which is how it came to
  ## disagree: it merged a double-keyed `foo.0.Ia.Ib.mod` the shared predicate
  ## rejects. Roles that are private to one module — a closure environment, a
  ## vtable, a coroutine frame — are kept OUT of the key slot at the mint site
  ## (`symparser.derivedName` puts the tag inside the identifier: `` outer`env.0 ``),
  ## so they never reach this test at all.
  if isInstantiation(s):
    result = s[0 ..< s.rfind('.')]
  else:
    result = ""

proc markSymbolUsed*(ctx: var GenContext; fullName: string) =
  ## Mark a symbol as used, adding it to pending list if not yet generated.
  ## Both main module and foreign module symbols are subject to dead code elimination.
  ## Only symbols that are actually referenced (via lookupWithAutoImport) are marked as used.
  ## Handles deduplication: if symbol has a dedup key and we've seen that key before,
  ## the symbol is merged with the canonical one
  if fullName in ctx.generatedSymbols:
    return

  let dedupKey = extractDedupKey(fullName)
  if dedupKey != "":
    # Check if we already have a canonical symbol for this key
    if dedupKey in ctx.dedupTable:
      # Already have this key, merge by using existing canonical
      return
    else:
      # First occurrence of this key, register as canonical
      ctx.dedupTable[dedupKey] = fullName

  # Add to pending if not already there (for both main module and foreign symbols)
  if fullName notin ctx.generatedSymbols:
    ctx.pendingSymbols.add fullName

proc getCanonicalName*(ctx: GenContext; fullName: string): string =
  ## Get the canonical name for a symbol (for dedup merging)
  let dedupKey = extractDedupKey(fullName)
  if dedupKey != "" and dedupKey in ctx.dedupTable:
    result = ctx.dedupTable[dedupKey]
  else:
    result = fullName

proc importOrdinal*(ctx: var GenContext; libPath: string): int =
  ## The ordinal of `libPath` in the image's import table, importing it if this is
  ## the first mention. One accessor for all three callers so a library named by
  ## the main module and by a foreign one lands in a single entry.
  for lib in ctx.imports:
    if lib.name == libPath: return lib.ordinal
  result = ctx.imports.len + 1
  ctx.imports.add ImportedLib(name: libPath, ordinal: result)

proc extprocLib*(ctx: var GenContext; n: var Cursor): int =
  ## The import-table ordinal an `(extproc :name "extname" "dll"? …)` binds to,
  ## consuming the optional dll operand.
  ##
  ## Every Windows extern carries it (arkham rejects one that names no library), so
  ## the decl is self-contained — which is what lets it be read anywhere, including
  ## the indexed jump `resolveForeignSym` reaches a foreign module's decls by, where
  ## no enclosing `(imp …)` is on any stack to consult. The Darwin form omits it and
  ## falls back to the module's single library.
  var libName = ""
  if n.kind == StrLit:
    libName = getStr(n)
    inc n
  if libName.len > 0:
    result = ctx.importOrdinal(libName)
  elif ctx.imports.len > 0:
    result = ctx.imports[0].ordinal        # Mach-O: libSystem, the only one
  else:
    result = ctx.importOrdinal(
      if ctx.arch in {Arch.WinX64, Arch.WinA64}: WindowsKernelDll
      else: "/usr/lib/libSystem.B.dylib")

proc openForeignModule*(ctx: var GenContext; modname: string; n: Cursor) =
  ## Open a foreign module for LAZY, on-demand symbol resolution: read just its
  ## embedded NIF `.index` (symbol → byte offset) and keep the stream open. The
  ## module's declarations are NOT parsed here — `resolveForeignSym` parses each
  ## one only when its name is actually followed (nominal typing). Idempotent.
  if ctx.modules.hasKey(modname):
    return
  var modfile = ""
  let asmnif = ctx.baseDir / modname & ".asm.nif"
  let plain = ctx.baseDir / modname & ".nif"
  if fileExists(asmnif):
    modfile = asmnif
  elif fileExists(plain):
    modfile = plain
  else:
    error("Foreign module file not found: " & modname & " (tried: " & asmnif & ", " & plain & ")", n)
    return
  let fm = nifmodules.openForeignModule(modfile)
  if not fm.hasEmbeddedIndex:
    error("Foreign module has no embedded NIF index (reindex it): " & modfile, n)
  ctx.modules[modname] = LoadedModule(foreign: fm, loaded: true)
