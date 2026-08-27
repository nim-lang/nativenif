#
#           Arkham — native code generator for Leng
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## Enum-based builder for the typed asm-NIF that arkham feeds to `nifasm`.
##
## The asm-NIF tag vocabulary is **nifasm's own generated enums** (`A64Inst` /
## `X64Inst` for instructions/branches/`lab`/`stmts`, `NifasmDecl` for `proc`/
## `params`/`extproc`/… — all from nativenif's `model.nim`, generated from
## `doc/instructions.md`). Reusing them makes the assembler the single source
## of truth and compile-time-enforces that arkham only emits tags nifasm
## accepts. Registers are arkham's arch-neutral `machine.Reg` slots, rendered
## by the per-target `renderReg` shim (AArch64's `regName` unless a backend
## overrides it — `codegen_x64` installs `x64RegName`).
## Built as a `nifcore` `TokenBuf` (the flexible NIF API) and serialized with
## `toString`.

import std / tables
import nifcore, nifcoreparse
import "../../nifasm/core" / [model, tagpool]
                             # nifasm: A64Inst/NifasmDecl/NifasmType/NifasmExpr,
                             # and the seeded tag pool (with its escape tag)
import ../risc/machine_a64 as machine
                             # arkham: Reg, and the DEFAULT `renderReg` — AArch64's
                             # `regName`. The x64 and Cortex-M backends install their
                             # own, so this edge is only about the default argument.
import peephole              # the finished-shape rewrites, applied in `render`
export A64Inst, X64Inst, NifasmDecl, NifasmType, NifasmExpr, X64Flag
export RvInst  # the RV32-only mnemonics (`semihost`, `csrw`, `csrs`). Three, and
               # all three are things no other target here has: the semihosting
               # escape is a sequence rather than a breakpoint, and a CSR write is
               # how a RISC-V image turns its own FPU on.
export MInst   # the Cortex-M-only mnemonics (`bkpt`, `bx`, `uxtb`, …). Everything
               # else the Cortex-M target uses is spelled with the SHARED tags, so
               # `A64Inst` covers it — see doc/instructions.md.

type
  AsmBuf* = object
    buf: TokenBuf
    ids: Table[string, TagId]   ## spelling → interned tag id (cache)
    renderReg*: proc (r: Reg): string {.nimcall.}  ## GPR slot → arch spelling shim
    immAnyDest*: bool           ## target carries an immediate into any `mov`
                                ## destination (x86-64 does, AArch64 does not)
    arch*: string               ## "x64"/"a64": selects the BodyLib entries the
                                ## peephole may splice (a body is target machine
                                ## code; a fingerprint match alone must not do)

proc initAsmBuf*(): AsmBuf =
  ## Defaults the register shim to AArch64 spellings; the x86-64 backend
  ## overrides `renderReg` after construction.
  ##
  ## The buffer takes nifasm's SEEDED tag pool rather than a fresh one: that
  ## pool is the one that nominates an escape tag, and asm-NIF's vocabulary
  ## overflows the 9-bit tag field (see `nifasm/tagpool`). With a fresh pool the
  ## overflowing spellings would have nowhere to go.
  AsmBuf(buf: createTokenBuf(256, sharedTags = createAsmTagPool()),
         ids: initTable[string, TagId](), renderReg: regName)

proc openS(a: var AsmBuf; spelling: string) {.inline.} =
  a.buf.openTag a.ids.mgetOrPut(spelling, a.buf.tags.registerTag(spelling))

proc open*[T: enum](a: var AsmBuf; t: T) {.inline.} = a.openS($t)
proc close*(a: var AsmBuf) {.inline.} =
  a.buf.closeTag()

template tree*[T: enum](a: var AsmBuf; t: T; body: untyped) =
  ## Open a tagged node named after the enum value's spelling (`$t`), run
  ## `body` to emit its children, then close. Use with `A64Inst`/`NifasmDecl`.
  a.openS($t)
  body
  a.close()

proc keyword*[T: enum](a: var AsmBuf; t: T) {.inline.} =
  ## A childless tag, e.g. `(extcall)` / `(params)`.
  a.openS($t); a.close()

proc rawReg*(a: var AsmBuf; r: Reg) {.inline.} =
  ## The PHYSICAL register `(xN)`/`(r5)`/`(rax)` — a childless tag named after
  ## the register via the (per-target) `renderReg` shim.
  ##
  ## Raw is a claim, not a default. A backend has exactly two ways to write a
  ## register down and they are not interchangeable: this one, which says "the
  ## hardware register itself", and the emitters' `emReg`, which says "whatever
  ## value currently lives there" and spells a bound register by its checked
  ## name. Reaching for this one where a value was meant emits a raw register
  ## where nifasm expected a symbol, and — worse — walks straight past the
  ## unbound-scratch assertion that exists to catch a temporary which escaped
  ## the binder. Hence the name: every call site below is a deliberate statement
  ## that no value is being named here.
  ##
  ## Legitimately raw: a `(clobber …)` or `(param …)` DECLARATION, the frame
  ## save/restore of a callee-saved register, `SP`, and the hand-written bodies
  ## (the 64-bit dividers, the semihosting shims) that are not allocator output
  ## at all.
  a.openS(a.renderReg r); a.close()

proc dreg*(a: var AsmBuf; f: FReg) {.inline.} =
  ## A double-precision fp register operand `(dN)` (the 64-bit view of `vN`).
  a.openS("d" & $ord(f)); a.close()

proc sreg(a: var AsmBuf; f: FReg) {.inline.} =
  ## A single-precision fp register operand `(sN)` (the 32-bit view of `vN`).
  a.openS("s" & $ord(f)); a.close()

proc freg*(a: var AsmBuf; f: FReg; bits: int) {.inline.} =
  ## An fp register operand sized by `bits` (32 → `(sN)`, else `(dN)`).
  if bits == 32: a.sreg f else: a.dreg f

proc xmmReg*(a: var AsmBuf; f: FReg) {.inline.} =
  ## An x86-64 SSE register operand `(xmmN)`. Unlike AArch64's `(sN)`/`(dN)`, the
  ## precision is carried by the instruction (movss vs movsd), not the register.
  a.openS("xmm" & $ord(f)); a.close()

proc sym*(a: var AsmBuf; s: string) {.inline.} = a.buf.addSymUse s     # use
proc symDef*(a: var AsmBuf; s: string) {.inline.} = a.buf.addSymDef s  # :def
proc str*(a: var AsmBuf; s: string) {.inline.} = a.buf.addStrLit s
proc intLit*(a: var AsmBuf; v: int64) {.inline.} = a.buf.addIntLit v
proc ident*(a: var AsmBuf; s: string) {.inline.} = a.buf.addIdent s

# ── type emission (NifasmType tags) ─────────────────────────────────────────
# Kept here (not in codegen) because nifasm's NifasmType shares spellings with
# nimony's LengType — referencing the nifasm enum values is unambiguous only in
# this module, which doesn't import nifcdecl.

proc intType*(a: var AsmBuf; bits: int) = a.tree IT: a.intLit bits
proc uintType*(a: var AsmBuf; bits: int) = a.tree UT: a.intLit bits
proc charType*(a: var AsmBuf; bits: int) = a.tree CT: a.intLit bits
proc floatType*(a: var AsmBuf; bits: int) = a.tree FT: a.intLit bits
proc boolType*(a: var AsmBuf) = a.keyword BoolT
proc voidType*(a: var AsmBuf) = a.keyword VoidT
proc nilValue*(a: var AsmBuf) = a.keyword NilT
  ## `(nil)` — the null pointer. Serves DOUBLE duty: as a value operand
  ## (`(mov r (nil))`, `(cmp r (nil))`) and as a register-binding TYPE
  ## (`(rebind :t (nil) …)`). nifasm reads it as a 0 immediate of the `nil`
  ## type (compatible with any pointer, never a sized integer).

template objectType*(a: var AsmBuf; body: untyped) = a.tree ObjectT: body
template unionType*(a: var AsmBuf; body: untyped) = a.tree UnionT: body
template ptrType*(a: var AsmBuf; body: untyped) = a.tree PtrT: body
template aptrType*(a: var AsmBuf; body: untyped) = a.tree AptrT: body
template arrayType*(a: var AsmBuf; body: untyped) = a.tree ArrayT: body
template flexarrayType*(a: var AsmBuf; body: untyped) = a.tree FlexarrayT: body
template proctypeType*(a: var AsmBuf; body: untyped) = a.tree ProctypeT: body
template fldDef*(a: var AsmBuf; name: string; body: untyped) =
  a.openS($FldT)
  a.symDef name
  body
  a.close()

# ── inline assembler (NIF-text fragments) ───────────────────────────────────
# NIF text *is* the DSL: rather than invent a separate assembly syntax, a
# multi-instruction lowering can be written as the very asm-NIF nifasm already
# consumes, parsed and spliced straight into the buffer. Operands are filled in
# by the caller with ordinary string building (`regName r`, `$bits`, …) — e.g.
#   g.ab.splice "(fmov (" & regName tmp & ") (d0)) (lsr (x0) (x0) 32)"

proc splice*(a: var AsmBuf; nifText: string) =
  ## Parse one or more sibling asm-NIF nodes from `nifText` and append them to
  ## the buffer. The fragment uses nifasm's tag vocabulary and arkham's register
  ## spellings (`(fadd (d0) (d1) (d2))`, `(x9)`, …) — i.e. exactly what `render`
  ## would have produced via the enum builder. Parsing shares the buffer's pool
  ## and tag namespace, so splicing is a bulk copy (no re-interning).
  var frag = parseFromBuffer("(stmts " & nifText & ")", "arkham.inline",
                             sizeHint = 32, sharedPool = a.buf.pool,
                             sharedTags = a.buf.tags)
  var c = frag.beginRead()                   # at the throwaway `(stmts …)` wrapper
  c.into:                                    # splice only its children
    while c.hasMore:
      a.buf.addSubtree c
      skip c

proc sideBuf*(a: AsmBuf): AsmBuf =
  ## A detached buffer sharing this one's literal pool + tag namespace, so
  ## appending it back (`append`) is a bulk copy. The body-buffer trick: the
  ## emitter writes a proc's body here first, then writes the prologue — whose
  ## shape (callee-saved pushes, alignment pad, the `(s)` region `sub`) is only
  ## final once the body has been emitted — into the main buffer, and appends
  ## the body after it.
  AsmBuf(buf: createTokenBuf(256, a.buf.pool, a.buf.tags),
         ids: a.ids, renderReg: a.renderReg, immAnyDest: a.immAnyDest,
         arch: a.arch)

proc append*(a: var AsmBuf; other: var AsmBuf) =
  ## Append every top-level node of `other` (a `sideBuf` of `a`; the shared
  ## pools make each copy a bulk `copyMem`).
  var c = other.buf.beginRead()
  while c.hasMore:
    a.buf.addSubtree c
    skip c
  endRead c

proc render*(a: var AsmBuf; dottedSuffix = ""): string =
  ## Serialize to a full NIF module for nifasm: `(.nif27)` header, body, and a
  ## trailing embedded `(.index …)` (so nifasm resolves cross-module symbols
  ## lazily by their indexed byte offset). `dottedSuffix` (e.g. `.mymod`)
  ## compresses self-module symbol suffixes to a trailing dot.
  ##
  ## The peephole runs HERE, on the finished buffer, so it sees the shapes the
  ## emitters produce rather than the intentions behind them (see peephole.nim).
  ## `-d:arkhamNoPeephole` turns it off for a bisect.
  when not defined(arkhamNoPeephole):
    discard peephole(a.buf, a.immAnyDest)
  toModuleString(a.buf, dottedSuffix)
