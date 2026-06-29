#       ghast — SPIR-V NIF renderer (real textual syntax)
# (c) Copyright 2026 Andreas Rumpf
#
# See the file "license.txt", included in this distribution.

## Renders a SPIR-V-as-NIF buffer (see `spirv.nim`) into the real, textual SPIR-V
## assembly syntax — the form `spirv-as` consumes and `spirv-dis` produces:
##
##   ; SPIR-V
##   ; Version: 1.3
##   OpCapability Shader
##   OpMemoryModel Logical GLSL450
##   %void = OpTypeVoid
##   %main = OpFunction %void None %fnty
##   …
##
## The mapping is purely structural, so it is opcode-agnostic (it renders any
## instruction the codegen emits, not a fixed list): a leading `SymbolDef` child
## becomes the `%id =` result assignment; remaining children render by token
## kind — `Symbol` → `%id`, `Ident` → bare enum word, `StrLit` → `"quoted"`,
## `IntLit` → the number. This module is usable both as a library (`renderSpirv`,
## called in-process by `ghast`) and as a standalone CLI on a dumped `.spv.nif`.

import std / assertions
import nifcore, nifcoreparse

proc idName(sym: string): string =
  ## A SPIR-V id's display name: the symbol with its NIF module suffix (the
  ## `.0` that makes it serialise as a symbol — see `spirv.idSuffix`) stripped.
  result = sym
  for i in 0 ..< sym.len:
    if sym[i] == '.':
      result = sym[0 ..< i]
      break

proc fmtOperand(c: Cursor): string =
  ## One operand token in SPIR-V spelling. (Operands are always atoms.)
  case c.kind
  of Symbol, SymbolDef: result = "%" & idName(symName(c))
  of Ident: result = strVal(c)
  of StrLit: result = "\"" & strVal(c) & "\""
  of IntLit: result = $intVal(c)
  of UIntLit: result = $uintVal(c)
  else: result = "?"

proc renderSpirv*(b: var TokenBuf): string =
  ## Walk the `(Module …)` NIF tree and emit textual SPIR-V.
  var instrs: seq[string] = @[]
  var bound = 1                      # SPIR-V `Bound` = max result id + 1
  var c = b.beginRead()
  assert c.kind == TagLit and tagName(c.tags, c.cursorTagId) == "Module",
    "renderSpirv: root is not a (Module …) tree"
  c.into:
    while c.hasMore:
      assert c.kind == TagLit, "renderSpirv: expected an instruction tag"
      let op = tagName(c.tags, c.cursorTagId)
      var resultId = ""
      var ops: seq[string] = @[]
      var first = true
      c.into:
        while c.hasMore:
          if first and c.kind == SymbolDef:
            resultId = idName(symName(c))
            inc bound
            inc c
          else:
            ops.add fmtOperand(c)
            inc c
          first = false
      var line = ""
      if resultId.len > 0: line = "%" & resultId & " = "
      line.add op
      for o in ops: line.add " " & o
      instrs.add line
  var lines = @[
    "; SPIR-V",
    "; Version: 1.3",
    "; Generator: ghast",
    "; Bound: " & $bound,
    "; Schema: 0"]
  for ln in instrs: lines.add ln
  result = ""
  for i, ln in lines:
    if i > 0: result.add "\n"
    result.add ln

when isMainModule:
  import std / [os, syncio]
  if paramCount() < 2:
    quit "usage: render <module.spv.nif> <out.spvasm>"
  var buf = parseFromFile(paramStr(1))
  writeFile(paramStr(2), renderSpirv(buf))
