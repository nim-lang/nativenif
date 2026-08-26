#
#           Arkham — native code generator for Leng
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#


## Addressing: turning an lvalue into a `(mem …)` operand, and the loads and
## stores that go through one.
##
## x86 reaches memory from almost every instruction, so this is where most of
## the target's leverage is — and most of its risk: `emLvalAddr2` walks a whole
## lvalue tree emitting base + index*scale + disp, and every scratch register it
## materialises on the way has to be released again in the same order
## (`unbindLvalTemps2`), or the pool leaks across statements.

import std / [assertions, tables, sets]
import nifcore, nifcdecl
import "../core" / [asmslots, machinedesc, planer, programs, asmbuf,
                    context, diag, typeutil, 
                    mirrors, exprpred, typenav, regbind]
import "../../nifasm/image/tracetable"
import machine as machine_x64
import emit

const arkhamNameAggrBase* = not defined(arkhamNoNameAggrBase)
  ## Address a register-homed pointer-to-aggregate BY NAME in field accesses, and
  ## declare the by-reference aggregate parameters that had no declaration at all, so
  ## `rb` and nifasm's binding checker can both see them. `-d:arkhamNoNameAggrBase`
  ## restores the old raw-register form.
  ##
  ## This is the prerequisite for retiring `regFreeForTemp`'s `regHoldsHome` union
  ## (54.8 % of every "out of registers" verdict): while these pointers were unnamed,
  ## that per-proc union was the ONLY thing reserving their registers.
  ##
  ## Turning it on is also what first made nifasm's call-safety checker able to see
  ## them, and it immediately reported `syms.1` in `collectExplicitInstMatches.0.` —
  ## a by-reference aggregate parameter left bound to **rdx** across three calls. The
  ## allocator was right (the analyser counts a field read THROUGH the pointer as a
  ## use, so a pointer read after a call is denied `AllRegs` and gets a callee-saved
  ## home — verified). What was missing was the FLUSH: see `emitParamMoves`.

proc emWordThroughPtr*(g: var CodeGen; p: Reg; idx: int)

proc emReg*(g: var CodeGen; r: Reg) {.inline.} =
  ## A value register operand. If `r` currently hosts a named local, emit the
  ## local's *name* (a typed symbol nifasm type-checks); otherwise the raw `(reg)`
  ## tag (a transient scratch register).
  let nm = g.rb.boundName(r)
  if nm.len > 0: g.ab.sym nm
  else:
    # The volatile scratch pool (r10/r11) is the ONLY register class the allocator
    # hands out for arbitrary computed values; every such hand-out — pool, steal, and
    # staging — is now `bindTemp`'d to a checked name (see `pickStaging`/the spill
    # paths), so a *raw* pool register reaching here means an unbound scratch
    # slipped past the binder: the silent-clobber hole this work closes. Every OTHER
    # register has an irreducible structural raw use and is allowed: rax/rdi/rsi/rdx/
    # r8/r9 are the syscall + call-argument / return ABI registers; rcx is the 4th call
    # arg; rsp/rbp are the frame/segment bases; rbx/r12–r15 are callee-saved param
    # homes. (The fixed rcx/rdx/rsi/r8 scratch *inside* the self-contained mem* /
    # byte-copy loops is nonetheless bound there, for extra checker coverage.)
    assert r notin g.md.intTempRegs and r != R11,
      "arkham x64: unbound scratch/bridge register reached emReg: " & x64RegName(r) &
      " in " & gArkhamCurProc &
      " — every value/address-carrying R10/R11 use must be a typed binding (pickStagingSealed/bindTemp)"
    g.ab.rawReg r

proc pickStagingSealed*(g: var CodeGen; what: string; slot: AsmSlot; avoid: Reg = NoReg): Reg =
  ## A transient caller-saved staging register, sealed so a nested pick cannot
  ## reuse it until `giveBack` releases it; fails loudly when none is free (the
  ## reserved R11 bridge makes that near-impossible). `avoid` keeps the pick off a
  ## register the caller still needs live (e.g. an accumulator that is not a bound
  ## temp, so `pickStagingScratch`'s own filters would not otherwise exclude it).
  result = g.pickStagingScratch(avoid)
  if result == NoReg:
    # Genuinely out of registers: every candidate is `avoid`, sealed, a live local
    # home, or a live temp. The fix is to need fewer live values here, not to
    # invent a register — see design.md on why the emitter has no spiller.
    raiseAssert "arkham x64n: no staging register for " & what &
                " in proc " & g.curProcName & g.stagingCensus(avoid)
  g.plan.seal result
  g.bindTemp(result, slot)
  g.stagingNote(result, what)

proc fmovFromGpr*(g: var CodeGen; d: FReg; s: Reg; bits: int) =     # movfd/movfq xmm ← gpr
  let op = if bits == 32: MovfdX64 else: MovfqX64
  g.ab.tree op: g.emFReg d; g.emReg s

proc fmovToGpr*(g: var CodeGen; d: Reg; s: FReg; bits: int) =       # movfd/movfq gpr ← xmm
  # The other direction of the same instruction; nifasm picks gpr→xmm vs xmm→gpr
  # from which operand is the xmm one, so only the operand ORDER differs here.
  let op = if bits == 32: MovfdX64 else: MovfqX64
  g.ab.tree op: g.emReg d; g.emFReg s

proc fcvtI2F*(g: var CodeGen; d: FReg; s: Reg; bits: int) =         # cvtsi2ss/sd xmm ← gpr
  let op = if bits == 32: Cvtsi2ssX64 else: Cvtsi2sdX64
  g.ab.tree op: g.emFReg d; g.emReg s

proc fcvtF2I*(g: var CodeGen; d: Reg; s: FReg; bits: int) =         # cvttss2si/sd2si gpr ← xmm
  let op = if bits == 32: Cvttss2siX64 else: Cvttsd2siX64
  g.ab.tree op: g.emReg d; g.emFReg s

proc movImm*(g: var CodeGen; d: Reg; v: int64) =
  g.ab.tree MovX64: g.emReg d; g.ab.intLit v

proc movReg*(g: var CodeGen; d, s: Reg) =
  ## THE reg→reg move. Both ends are NAMES when they carry bindings, and nifasm
  ## checks the names' declared types, not the machine move — which moves the whole
  ## register whatever the two sides call it. Where they disagree the move is a
  ## reinterpretation, so say so with a `(cast …)` rather than emit something that
  ## reads as a narrowing move; `genStore2` already answers a pointer field that way.
  ## The destination's type is not ours to change here: it is a named local's, and
  ## it is right. (A retype that is genuinely wrong is a bug at the PRODUCER — see
  ## `emitCast2`'s pre-retype and `restoreBindings` — and this does not paper over
  ## those: they decide what the binding says, this only spells the move honestly.)
  if d == s: return
  let dt = g.bindTypeOf(d)
  if not cursorIsNil(dt):
    let st = g.bindTypeOf(s)
    if not cursorIsNil(st) and bindTypeDiffers(g.prog, st, dt):
      var dtc = dt
      g.ab.tree MovX64:
        g.emReg d
        g.ab.tree CastX: (g.genTypeBody(dtc); g.emReg s)
      return
  g.ab.tree MovX64: g.emReg d; g.emReg s

proc binReg*(g: var CodeGen; op: X64Inst; d, s: Reg) =      # d op= s
  g.ab.tree op: g.emReg d; g.emReg s

proc binImm*(g: var CodeGen; op: X64Inst; d: Reg; v: int64) =  # d op= imm
  ## `imul r, 2^k` is a shift: hexer lowers `p + i*sizeof(T)` to a runtime
  ## multiply even after `sizeof` folds to 4/8, and GCC turns that into
  ## `shl` / a SIB scale. Catching it here covers both the canonical and
  ## swapped emitBin2 paths (and every other immediate-mul).
  ##
  ## NOT under `keepovf`: the two agree on the low 64 bits and DISAGREE on the
  ## flags. `imul` sets OF/CF exactly when the product overflows, which is what
  ## the mandatory `(ovf)` right after reads via `jo`/`jb`; `shl` leaves OF
  ## UNDEFINED for counts > 1 and puts the last bit shifted out in CF, so `x * 8`
  ## would read a garbage overflow answer. `noFoldPos >= 0` marks exactly that
  ## emission window (genStmt2's KeepovfS sets it around its store).
  ## The a64 twin needs no such gate: its `KeepovfS` builds the `mul` + `smulh`/
  ## `umulh` sequence itself via `binReg`, never through this immediate fold.
  if op == ImulX64 and v >= 2 and (v and (v - 1)) == 0 and g.noFoldPos < 0:
    var k = 0'i64
    var t = v
    while t > 1: (t = t shr 1; inc k)
    g.ab.tree ShlX64: g.emReg d; g.ab.intLit k
    return
  g.ab.tree op: g.emReg d; g.ab.intLit v

proc extendTo*(g: var CodeGen; dest: Reg; width: int; signed: bool) =
  ## Normalize the low `width` bits of `dest` to its full 64-bit register form
  ## (sign- or zero-extended). No-op for 64-bit. arkham keeps every scalar
  ## 64-bit-wide in a register, so widths are normalized explicitly rather than
  ## relying on sized loads.
  ##
  ## 8/16/32 go through `movzx`/`movsx`, which is exactly this operation in ONE
  ## instruction (3-4 bytes). The generic `shl #(64-w); sar|shr #(64-w)` pair is
  ## kept only for the widths x86 has no extension form for — nothing emits those
  ## today, but the fallback keeps the helper total.
  if width <= 0 or width >= 64: return
  if width in {8, 16, 32}:
    g.ab.tree (if signed: MovsxX64 else: MovzxX64):
      g.emReg dest; g.emReg dest; g.ab.intLit int64(width)
    return
  let sh = int64(64 - width)
  g.binImm(ShlX64, dest, sh)
  g.binImm(if signed: SarX64 else: ShrX64, dest, sh)

proc cmpZero*(g: var CodeGen; r: Reg) =
  ## `cmp r, 0` as `test r, r`: 3 bytes instead of 7, and every flag is identical
  ## (both clear CF/OF and set ZF/SF/PF from the same value), so it is valid under
  ## any condition code. 2326 sites in a self-hosted image.
  g.binReg(TestX64, r, r)

proc emGlobalAddr*(g: var CodeGen; dest: Reg; name: string) =
  ## `dest ← &global` — RIP-relative `lea` (nifasm resolves the gvar to a
  ## `.bss`/`.data` address). x86-64 has no typed RIP-relative memory operand, so
  ## a global is always accessed by first materializing its address. An importc/
  ## exportc gvar is referenced by its bare C name (cross-module linkage).
  g.ab.tree LeaX64: (g.emReg dest; g.ab.sym g.prog.gvarRefName(name))

proc emTvarAddr*(g: var CodeGen; dest: Reg; name: string) =
  ## `dest ← &threadvar` — the FS base block address plus the tvar's FS offset, folded
  ## into one `lea` (nifasm resolves the tvar symbol to that offset). x86-64 has no
  ## FS-relative `lea`, so the address is `&arkham.tls.0 + offset`. Mirror of the Tvar
  ## arm of `aggrAddrInto`; used to marshal a thread-local aggregate call argument.
  ##
  ## `name` may be a FOREIGN tvar (declared in another bundled module — e.g. a closure
  ## environment threadvar): nifasm whole-program-links, so its lea offset resolver
  ## (`lookupWithAutoImport`) imports the foreign `(tvar …)` decl and allocates its FS
  ## offset in the SAME unified `arkham.tls.0` block. Local and foreign emit identically.
  g.emGlobalAddr(dest, TlsBlockName)                # dest ← FS base block
  g.ab.tree LeaX64: (g.emReg dest; g.emReg dest; g.ab.sym name)  # dest += tvar FS offset

proc emSymAddr*(g: var CodeGen; dest: Reg; dst: Location) =
  ## `dest ← &dst` for a module-level symbol destination — a global (RIP-relative lea)
  ## or a thread-local (FS base + offset). The ONE address-of behind every aggregate
  ## store into either, so the build-through-pointer logic dispatches only on the RHS
  ## kind, never on global-vs-threadvar.
  case dst.kind
  of Glob: g.emGlobalAddr(dest, dst.name)
  of Tvar: g.emTvarAddr(dest, dst.name)
  else: raiseAssert "arkham x64n: emSymAddr on " & $dst.kind

proc emSymAddrByName*(g: var CodeGen; dest: Reg; name: string) =
  ## `dest ← &name` for a module-level symbol, dispatching global vs thread-local by the
  ## symbol's CATEGORY — the lvalue-base twin of `emSymAddr` (which takes a resolved
  ## `Location`). `locationOfSym` returns `NoLoc` for both a global and a tvar (neither is
  ## a local), so the lvalue-base path can't tell them apart by storage; the category can.
  if g.lookupSym(name).cat == scTvar: g.emTvarAddr(dest, name)
  else: g.emGlobalAddr(dest, name)

proc binMem*(g: var CodeGen; op: X64Inst; dest: Reg; loc: Location) =
  ## `dest op= [rsp+slot]` — x86 folds a `NamedStack` memory source into the ALU op.
  ## (A `Mem` access chain folds through `binMemLval2` instead.)
  assert loc.kind == NamedStack, "arkham x64: binMem on location kind " & $loc.kind
  g.ab.tree op:
    g.emReg dest
    g.emStackMem(loc.name)

proc emMemAt*(g: var CodeGen; p: Reg; pointee: Cursor) =
  ## `(mem (cast (ptr T) p))` — dereference `p` typed as `ptr T` so nifasm sizes the
  ## access to T's width. The atomic memory operand MUST carry the pointee type: an
  ## untyped `(mem p)` defaults to a 64-bit access, so an atomic on a sub-64-bit lock
  ## word (e.g. a `uint32` field) would read/WRITE 8 bytes and clobber the adjacent
  ## field — the same width bug `intMemAccess` fixed for plain `cmp [mem],imm`.
  g.ab.tree MemX:
    g.ab.tree CastX:
      var t = pointee
      g.ab.ptrType: g.genTypeBody(t)
      g.emReg p

proc emByteAt*(g: var CodeGen; base, idx: Reg) =
  ## `(mem (at (cast (aptr (u 8)) base) idx))` — the byte at `base[idx]`. The cast
  ## types the raw register as a byte-array pointer so nifasm sizes the access to
  ## one byte (a load zero-extends into the 64-bit register, a store writes the
  ## low byte only — see `intMemAccess` in the assembler).
  g.ab.tree MemX:
    g.ab.tree AtX:
      g.ab.tree CastX:
        g.ab.aptrType: g.ab.uintType(8)
        g.emReg base
      g.emReg idx

proc emLoadByte*(g: var CodeGen; dest, base, idx: Reg) =
  g.ab.tree MovX64: (g.emReg dest; g.emByteAt(base, idx))

proc emStoreByte*(g: var CodeGen; base, idx, src: Reg) =
  g.ab.tree MovX64: (g.emByteAt(base, idx); g.emReg src)

proc emQwordAt*(g: var CodeGen; base, idx: Reg) =
  ## `(mem (at (cast (aptr (u 64)) base) idx))` — the QUADWORD at `base[idx]`, i.e.
  ## byte offset `idx*8`: `at` scales the index by the element type, and 8 is a legal
  ## SIB scale, so this is still a single addressing mode. `idx` therefore counts
  ## quadwords, not bytes.
  g.ab.tree MemX:
    g.ab.tree AtX:
      g.ab.tree CastX:
        g.ab.aptrType: g.ab.uintType(64)
        g.emReg base
      g.emReg idx

proc emQwordThru(g: var CodeGen; base: Reg) =
  ## `(mem (cast (ptr (u 64)) base))` — the quadword at `[base]`, no index.
  g.ab.tree MemX:
    g.ab.tree CastX:
      g.ab.ptrType: g.ab.uintType(64)
      g.emReg base

proc emLoadQword*(g: var CodeGen; dest, base: Reg) =
  g.ab.tree MovX64: (g.emReg dest; g.emQwordThru(base))

proc emLoadQwordAt*(g: var CodeGen; dest, base, idx: Reg) =
  g.ab.tree MovX64: (g.emReg dest; g.emQwordAt(base, idx))

proc emStoreQword*(g: var CodeGen; base, idx, src: Reg) =
  g.ab.tree MovX64: (g.emQwordAt(base, idx); g.emReg src)

proc emBroadcastByte*(g: var CodeGen; dest, src, scratch: Reg) =
  ## `dest` ← the low byte of `src` replicated into all eight lanes, so one quadword
  ## store paints eight bytes. Doubling by shift+or rather than
  ## `imul dest, 0x0101010101010101`: the multiplier does not fit an x86 immediate,
  ## so that form would cost a `mov imm64` anyway and then a 3-cycle multiply.
  ## `dest`, `src` and `scratch` must be three distinct registers.
  g.movReg(dest, src)
  g.binImm(AndX64, dest, 0xFF)
  for sh in [8'i64, 16, 32]:
    g.movReg(scratch, dest)
    g.binImm(ShlX64, scratch, sh)
    g.binReg(OrX64, dest, scratch)

proc emCmpReg*(g: var CodeGen; a, b: Reg) =
  g.ab.tree CmpX64: (g.emReg a; g.emReg b)

proc genRepMovsFwd*(g: var CodeGen; nReg: Reg) =
  ## ASCENDING block copy of `nReg` BYTES from `[rsi]` to `[rdi]`: `rep movsq` for the
  ## 8-byte bulk, `rep movsb` for the ≤7-byte tail.
  ##
  ## The string instructions take their operands implicitly and DESTROY rdi, rsi and rcx
  ## (both pointers advance past the copied block, rcx ends at 0), so the caller must
  ## have saved anything it still needs — `nReg` must therefore not be one of them.
  ## nifasm records the same clobber set (see `RepmovsbX64` in the assembler), and the
  ## register mirror is dropped here so no cached value survives the copy. DF is 0
  ## throughout an arkham program (SysV guarantees it at entry and at every call, and
  ## arkham never emits `std`), so `movs` always steps upward.
  ##
  ## Quadword bulk + byte tail rather than a lone `rep movsb`: without ERMSB the byte
  ## form moves one byte per iteration, and the two extra `mov`s plus a possibly
  ## zero-count second `rep` are cheap next to that. (On ERMSB/FSRM parts a bare
  ## `rep movsb` would edge it out; not worth a CPU-feature split here.)
  g.movReg(RCX, nReg)
  g.binImm(ShrX64, RCX, 3)                     # quadwords = n div 8
  g.ab.keyword RepmovsqX64
  g.movReg(RCX, nReg)
  g.binImm(AndX64, RCX, 7)                     # tail bytes = n mod 8
  g.ab.keyword RepmovsbX64

proc emStackAddr*(g: var CodeGen; dest: Reg; name: string) =   # dest ← &stackvar
  ## `dest` is often an ABI argument register that still carries a dead
  ## scalar local (x86-64 homes AllRegs locals in rdi/rsi/…). `emReg` would
  ## emit that name, and nifasm rejects `(lea boolName, &struct)`. Drop a
  ## non-pointer binding; a pointer-typed dest (the assignment `p = addr x`)
  ## is kept.
  if g.rb.isBound(dest) and not g.rb.isBoundTemp(dest) and not g.rb.isPtrBound(dest):
    g.releaseStaleName(dest)
  g.ab.tree LeaX64: (g.emReg dest; g.ab.sym name)

proc emAggrHomeAddr*(g: var CodeGen; dest: Reg; name: string) =
  ## `dest ← &<the aggregate stored under `name`>`, for a name that is a stack home:
  ## the SLOT's address, or — when the home is a `StackPtr` — the pointer the slot
  ## HOLDS. Unlike `emAggrSrcAddr` this stays rsp-relative, so it also serves a
  ## SYNTHETIC slot (an `aggtmp` built for an inline constructor), whose home the
  ## allocator does not track.
  let home = g.plan.homeOfSym(name)
  if home.kind == StackPtr:
    g.ab.tree MovX64: (g.emReg dest; g.emStackMem(home.ptrName))
  else:
    g.emStackAddr(dest, name)

proc emPtrFieldMem*(g: var CodeGen; ptrReg: Reg; typeSym: SymId; field: string) =
  ## `(mem (dot (cast (ptr T) reg) field))` — a field through a register holding a
  ## pointer to the aggregate (a >16B by-ref param / the indirect-result buffer).
  ## The cast types the bare register so nifasm can compute the field offset.
  g.ab.tree MemX:
    g.ab.tree DotX:
      g.ab.tree CastX:
        g.ab.ptrType: g.emTypeSym(typeSym)
        g.emReg ptrReg
      g.ab.sym field

proc emAggrPtrBase(g: var CodeGen; nm: string) =
  ## Name the register that carries the pointer to aggregate `nm` — or, when the
  ## register carries no binding for it, fall back to the bare register.
  ##
  ## The fallback is a MEASURE OF THE REMAINING HOLE, not a design: every time it
  ## fires, a live pointer sits in a register that `rb` and nifasm's binding checker
  ## cannot see. `-d:arkhamRawBaseDbg` counts and names them. **Two sites in a whole
  ## nifbench build**, both the same shape: a by-ref aggregate param whose binding was
  ## released by the marshalling of a NORETURN call (`raiseAssert`), read again on the
  ## path that jumps over that call — where the pointer is still live. `AllRegs`
  ## deliberately permits a diverging call in a param's interval, so the value really
  ## is live there; only the binding is gone.
  ##
  ## `rawHomeRegs` picks the reservation back up for `regFreeForTemp`'s narrow filter,
  ## but only from HERE — a temp picked between the kill and this read would still be
  ## handed the register (the temp for the enclosing load is picked first). Closing
  ## that window is work for whoever turns `-d:arkhamNarrowHomes` on; the per-proc
  ## `regHoldsHome` union covers it today.
  let loc = g.plan.homeOfSym(nm)
  if arkhamNameAggrBase and loc.kind == InReg and g.rb.boundName(loc.r) == nm:
    g.ab.sym nm
  else:
    when defined(arkhamRawBaseDbg):
      stderr.writeLine "RAWBASE " & g.curProcName & " " & nm &
        (if loc.kind == InReg: " reg=" & $loc.r & " boundTo=" & g.rb.boundName(loc.r)
         else: " loc=" & $loc.kind)
    if loc.kind == InReg:
      g.rawHomeRegs.incl loc.r
      g.emReg loc.r
    else: g.ab.sym nm

proc emPtrFieldMemSym(g: var CodeGen; ptrSym: string; typeSym: SymId; field: string) =
  ## `(mem (dot (cast (ptr T) name) field))` — the same operand as `emPtrFieldMem`
  ## but naming the SYMBOL that owns the pointer instead of its register.
  ##
  ## Naming it is what makes the reservation visible. `emReg` renders a register by
  ## its binding only when one happens to be live, so the register form silently
  ## degrades to a bare `(rsi)` the moment the binding is not — and then nothing in
  ## `rb` knows the register is occupied. That is the whole reason the emitter's temp
  ## filter still has to consult `regHoldsHome`, the per-proc union of every register
  ## any local is EVER homed in (see `regFreeForTemp`): it is compensating for reads
  ## that dropped the name. Measured: a temp handed `rsi` in `collectSyms` while
  ## `t.0h67 (ptr Table…)` lived there produced `rsi = 7` and a segfault, and nothing
  ## in the asm-NIF flagged it.
  g.ab.tree MemX:
    g.ab.tree DotX:
      g.ab.tree CastX:
        g.ab.ptrType: g.emTypeSym(typeSym)
        g.emAggrPtrBase(ptrSym)
      g.ab.sym field

proc emAggrFieldMem*(g: var CodeGen; base, field: string) =
  ## Field memory operand for aggregate `base`: a `(s)` stack struct → direct dot;
  ## a pointer in a register (a by-ref param, or any pointer-to-aggregate local) →
  ## through the pointer, BY NAME (see `emPtrFieldMemSym`).
  let loc = g.plan.homeOfSym(base)
  case loc.kind
  of NamedStack: g.emFieldMem(base, field)
  of StackPtr:
    raiseAssert "arkham x64: spilled by-ref field must go through a loaded pointer: " & base
  of InReg:      g.emPtrFieldMemSym(base, g.varType[base], field)
  of InRegPair:
    raiseAssert "arkham x64: InRegPair field must go through pairFieldReg: " & base
  else:
    # a synthetic nifasm `(s)` slot (e.g. a constructor temp) is rsp-relative by
    # name, just like a `NamedStack` var — the allocator simply doesn't track it.
    if g.varType.hasKey(base): g.emFieldMem(base, field)
    else: raiseAssert "arkham x64 v0: aggregate base neither stack nor pointer: " & base

proc globalToRegs*(g: var CodeGen; name: string; typeSym: SymId; regs: openArray[Reg]) =
  ## Read a GLOBAL aggregate's words into the by-value ABI arg GPRs `regs[i] ← word i`.
  ## The global is RIP-relative (no stack slot), so its address goes into the staging
  ## bridge and each word is read through that pointer — a FULL eightbyte as a raw
  ## `(u 64)` word (handles packed fields), a trailing PARTIAL eightbyte field-typed.
  ## The read-side twin of `regsToStructThroughPtr`, for a global passed by value as a
  ## call argument (`equalStrings(s, "")` where `s` is a global `string`).
  let p = g.pickStagingSealed("a global aggregate call-arg address", AddrSlot)
  g.emGlobalAddr(p, name)
  let byteSize = aggrByteSize(g.prog, typeSym)
  for i in 0 ..< aggrWordCount(g.prog, typeSym):
    if byteSize - i * 8 >= 8:
      g.ab.tree MovX64: (g.emReg regs[i]; g.emWordThroughPtr(p, i))
    else:
      let fn = fieldAtOffset(aggrLayout(g.prog, typeSym), i * 8)
      g.ab.tree MovX64: (g.emReg regs[i]; g.emPtrFieldMem(p, typeSym, fn))
  g.giveBack p

proc tvarToRegs*(g: var CodeGen; name: string; typeSym: SymId; regs: openArray[Reg]) =
  ## Read a THREAD-LOCAL aggregate's words into the by-value ABI arg GPRs
  ## `regs[i] ← word i`. Like `globalToRegs`, but the address is the FS-relative
  ## thread-var address (`emTvarAddr`) rather than a RIP-relative global.
  let p = g.pickStagingSealed("a thread-local aggregate call-arg address", AddrSlot)
  g.emTvarAddr(p, name)
  let byteSize = aggrByteSize(g.prog, typeSym)
  for i in 0 ..< aggrWordCount(g.prog, typeSym):
    if byteSize - i * 8 >= 8:
      g.ab.tree MovX64: (g.emReg regs[i]; g.emWordThroughPtr(p, i))
    else:
      let fn = fieldAtOffset(aggrLayout(g.prog, typeSym), i * 8)
      g.ab.tree MovX64: (g.emReg regs[i]; g.emPtrFieldMem(p, typeSym, fn))
  g.giveBack p

proc placeImm*(g: var CodeGen; dest: Reg; loc: Location) =
  ## `mov dest, <imm>` — emits `(mov dest (nil))` for a nil so the register binds to
  ## the `(nil)` type, else the ordinary `movImm`.
  if isNilImm(loc):
    g.ab.tree MovX64: (g.emReg dest; g.ab.nilValue())
  else: g.movImm(dest, loc.ival)

proc normalizeBinWidth*(g: var CodeGen; resTypeC: Cursor; rD: Reg; op: X64Inst) =
  ## arkham keeps register values canonically sign/zero-extended to their full
  ## 64-bit form. `add`/`sub`/`mul`/`shl` on a sub-64-bit type can leave nonzero
  ## bits ABOVE the type width (shl overflow past the top bit, add carry, unsigned
  ## sub borrow) — so a following `shr` / unsigned-compare / `div` would read those
  ## stale bits. Re-normalize the result to restore the invariant. `!&`/`!$` in
  ## tinyhashes are the canonical case: `x shl 10'u32` overflowed into bits 32+ and
  ## the next `shr 6'u32` pulled them back down, diverging RTTI hashes from the C
  ## backend. (`and`/`or`/`xor`/`shr` of already-normalized operands stay normalized,
  ## so they need no fixup.)
  if op notin {AddX64, SubX64, ImulX64, ShlX64}: return
  let slot = typeToSlot(resTypeC)
  if slot.kind in {AInt, AUInt} and slot.size > 0 and slot.size < 8:
    g.extendTo(rD, slot.size * 8, signed = slot.kind == AInt)

proc normalizeUnaryWidth*(g: var CodeGen; resTypeC: Cursor; rD: Reg) =
  ## The `neg`/`not` twin of `normalizeBinWidth`. Both are computed 64-bit wide, so
  ## on a sub-64-bit type they leave bits ABOVE the type width: `~15'u8` is
  ## `0xFFFF_FFFF_FFFF_FFF0`, not `0xF0`, and a following unsigned compare (or
  ## `shr`, or `div`) reads the stale bits. Signed types need it too, but only at
  ## the boundary — `neg` of `-128'i8` is `+128`, whose i8 value is `-128` again.
  let slot = typeToSlot(resTypeC)
  if slot.kind in {AInt, AUInt} and slot.size > 0 and slot.size < 8:
    g.extendTo(rD, slot.size * 8, signed = slot.kind == AInt)

proc seedWork*(g: var CodeGen; work: Reg; val: Location) =
  ## Load the atomic's VALUE operand into the working register — a register copy, or
  ## `mov work, imm` when the allocator left it a literal (see `allocInstr`).
  if val.kind == Imm: g.placeImm(work, val)
  else: g.movReg(work, val.r)

proc workOp*(g: var CodeGen; op: X64Inst; work: Reg; val: Location) =
  ## `work <op>= val`, immediate or register.
  if val.kind == Imm: g.binImm(op, work, val.ival)
  else: g.binReg(op, work, val.r)

proc genAtomicLoopRmw*(g: var CodeGen; dst, pReg, work: Reg; val: Location;
                      pointee: Cursor; op: X64Inst) =
  ## `rax = [p]; loop: work = rax op val; lock cmpxchg [p], work; jne loop`. There
  ## is no lock-prefixed fetch form for and/or/xor that yields the old value, so
  ## spin on `cmpxchg` — whose comparand register is architecturally `rax`. The old
  ## value ends up there and moves to `dst` once the loop is left.
  let lDone = g.freshLabel()
  g.ab.tree MovX64: (g.emReg RAX; g.emMemAt(pReg, pointee))   # rax = [p]
  g.emitLoop:
    g.movReg(work, RAX)
    g.workOp(op, work, val)                         # work = rax op val (the new value)
    g.ab.tree LockX64:
      g.ab.tree CmpxchgX64:
        g.emMemAt(pReg, pointee)
        g.emReg work                                # if [p]==rax: [p]=work else rax=[p]
    g.emJcc(JeX64, lDone)                           # cmpxchg succeeded (ZF=1) → exit forward
  g.emLab(lDone)                                    # else fall to the back-edge and retry
  g.movReg(dst, RAX)

proc emitIntrinsicOps*(g: var CodeGen; op: IntrinsicOp; argBits: int;
                      dst, src0: Reg; rotCount: int64) =
  ## Emit one intrinsic row's instruction(s) on ALREADY-PLACED operands. Shared by
  ## the allocator-driven path (`emitInstr2`, which reads the placement out of
  ## `plan.locs`) and the `.assembler` path (`genAsmProc`, where the placement is
  ## the user's `.register` annotation) — they differ only in how `dst`/`src0`
  ## were chosen, never in what gets emitted. For an in-place row the caller has
  ## already seeded `dst` from operand 0 and passes `src0 == dst`.
  let bits = if argBits in {8, 16, 32}: 32 else: 64
  case op
  of BsfOp, CtzOp:
    # count-trailing-zeros == index of the least-significant set bit. `src == 0` is
    # undefined (the row says so); nimony's callers guard the zero case.
    g.ab.tree BsfX64: (g.emReg dst; g.emReg src0)
  of BsrOp:
    g.ab.tree BsrX64: (g.emReg dst; g.emReg src0)
  of ClzOp:
    # `__builtin_clz` counts leading zeros; BSR yields the index of the HIGHEST set
    # bit, and `clz == (W-1) - bsr`, which for a power-of-two W is `bsr xor (W-1)`.
    g.ab.tree BsrX64: (g.emReg dst; g.emReg src0)
    g.ab.tree XorX64: (g.emReg dst; g.ab.intLit(bits - 1))
  of PopcntOp, PopcountOp:
    g.ab.tree PopcntX64: (g.emReg dst; g.emReg src0; g.ab.intLit bits)
  of BswapPinnedOp, BswapOp:
    # x86 BSWAP r16 is undefined, so a 16-bit swap is a 32-bit BSWAP whose two low
    # bytes end up in bits 16..31 — shift them back down.
    if argBits == 16:
      g.ab.tree BswapX64: (g.emReg dst; g.ab.intLit 32)
      g.ab.tree ShrX64: (g.emReg dst; g.ab.intLit 16)
    else:
      g.ab.tree BswapX64: (g.emReg dst; g.ab.intLit bits)
  of RolOp:
    g.ab.tree RolX64: (g.emReg dst; g.ab.intLit rotCount)
  of RorOp:
    g.ab.tree RorX64: (g.emReg dst; g.ab.intLit rotCount)
  of StackPointerOp:
    # The one register arkham otherwise never lets a value be read out of: `rsp`
    # is the frame, and `asmPinReg` rejects it as a home for exactly that reason.
    # READING it is a different act — the value is copied out, the frame is
    # untouched — and it is the only way a program can say where it is on its own
    # stack.
    g.ab.tree MovX64: (g.emReg dst; g.ab.rawReg RSP)
  of TraceTableOp:
    # A RIP-relative `lea` against the label nifasm defines for the trace table
    # (`nifasm/tracetable.nim`). nifasm synthesizes both the label and the bytes;
    # arkham only has to name it, and naming it is what makes nifasm emit it at
    # all.
    g.ab.tree LeaX64:
      g.emReg dst
      g.ab.tree LabX64: g.ab.sym TraceInfoSymbol
  else:
    raiseAssert "arkham x64n: no lowering for intrinsic `" & IntrinsicNames[op] & "`"

proc emitInoutInstr2*(g: var CodeGen; c: Cursor; op: IntrinsicOp;
                     argCurs: seq[Cursor]) =
  ## `add(d, s)` in an ordinary proc: `(add <d's home> <s>)`. The destination is
  ## `(haddr d)`, and d's home is whatever the allocator gave it — a register, or
  ## an `(s)` slot, both of which x86 accepts as a destination directly.
  let row = IntrinsicRows[op]
  let tag = x64InoutTag(op)
  if tag == NopX64:
    lengError c, "`" & IntrinsicNames[op] & "` has no x86-64 two-address form",
              lengInfo(c)
  proc emitDest(g: var CodeGen; d: Cursor) =
    var inner = d
    var sym = d
    if d.kind == TagLit and d.exprKind == HaddrC:
      inner.into:
        sym = inner; skip inner
        while inner.hasMore: skip inner
    if sym.kind != Symbol:
      lengError d, "the destination of `" & IntrinsicNames[op] & "` must be a " &
                "`var` argument naming a local", lengInfo(d)
    let loc = g.plan.locationOfSym(symName(sym), cursorToPosition(g.buf[], sym))
    case loc.kind
    of InReg: g.emReg loc.r
    of NamedStack: g.emStackMem(loc.name)
    else:
      lengError d, "the destination of `" & IntrinsicNames[op] & "` has no " &
                "register or stack home", lengInfo(d)
  if row.arity == 1:
    g.ab.tree tag: g.emitDest(argCurs[0])
  else:
    # The source was already emitted and memo'd by the fused emitInstr2.
    let src = g.plan.planned(cursorToPosition(g.buf[], argCurs[1]))
    g.ab.tree tag:
      g.emitDest(argCurs[0])
      case src.kind
      of InReg: g.emReg src.r
      of Imm: g.ab.intLit src.ival
      of NamedStack: g.emStackMem(src.name)
      else:
        lengError argCurs[1], "unsupported source operand for `" &
                  IntrinsicNames[op] & "`", lengInfo(c)

proc emLvalAddr2*(g: var CodeGen; c: Cursor) =
  ## Emit the nifasm address sub-tree for lvalue `c` (the operand of a `(mem …)` /
  ## `(lea …)`), reading any embedded value register from its pre-allocated `locs`.
  ## v1 slice: a stack-var base (`(rsp) name`), a `dot` field over such a base or a
  ## `deref`, and a pointer `deref` (`(cast (ptr pointee) ptrReg)`).
  case c.kind
  of Symbol:
    let nm = symName(c)
    let loc = g.plan.locationOfSym(nm, cursorToPosition(g.buf[], c))
    if loc.kind == NoLoc:
      # a module-level global aggregate base: its address is in the pre-assigned base
      # register (materialized by prematLval2) — either the allocator's `locs[pos]` reg
      # or, for a transient load, the emit-time staging reg parked in `lvalGlobBase`.
      # Type it `(cast (ptr globalType) reg)` so the enclosing dot/at can compute the offset.
      let pos = cursorToPosition(g.buf[], c)
      let baseReg = (if g.lvalGlobBase.hasKey(pos): g.lvalGlobBase[pos]
                     else: g.plan.planned(pos).r)
      let si = g.lookupSym(nm)
      var d = si.decl
      inc d; skip d; skip d                             # (gvar …): name, pragmas → type
      g.ab.tree CastX:
        g.ab.ptrType:
          if d.kind == Symbol: g.ab.sym symName(d)
          else: g.genTypeBody(d)
        g.emReg baseReg
    elif loc.kind == InReg and g.varType.hasKey(nm):
      # a pointer-to-aggregate in a register (a >16B by-reference param, or any such
      # local) — type it via `(cast (ptr T) name)` so the enclosing dot/at can compute
      # the field offset. BY NAME, not by register: see `emPtrFieldMemSym`. `emReg`
      # would degrade to a bare `(rdi)` wherever the binding is not live, and then the
      # register looks free to every filter that asks `rb`.
      g.ab.tree CastX:
        g.ab.ptrType: g.emTypeSym(g.varType[nm])
        g.emAggrPtrBase(nm)
    elif loc.kind == StackPtr:
      # spilled by-ref POINTER: premat loaded it into lvalGlobBase; type it like
      # the InReg case so the enclosing dot/at can compute the field offset.
      let pos = cursorToPosition(g.buf[], c)
      g.ab.tree CastX:
        g.ab.ptrType: g.emTypeSym(loc.pointeeType)
        g.emReg g.lvalGlobBase[pos]
    elif loc.kind == InRegPair:
      raiseAssert "arkham x64n: address of InRegPair local " & nm
    else:                                               # a `(s)` stack-var base
      # ONE node, like every other arm: the slot symbol already means
      # `[rsp + slotOffset]`. This emitter is spliced into `(dot …)`/`(at …)`/
      # `(lea …)` operand positions, so it must never write two siblings.
      g.ab.sym nm
  of TagLit:
    case c.exprKind
    of DotC:
      g.ab.tree DotX:
        var cc = c
        cc.into:
          g.emLvalAddr2(cc); skip cc                    # base (stack var or deref)
          g.ab.sym symName(cc); skip cc                 # field name
          while cc.hasMore: skip cc
    of AtC:
      let atPos = cursorToPosition(g.buf[], c)
      g.ab.tree AtX:
        var cc = c
        cc.into:
          g.emLvalAddr2(cc); skip cc                    # base (stack array)
          case cc.kind                                  # index (nifasm scales it)
          of IntLit: g.ab.intLit intVal(cc)
          of UIntLit: g.ab.intLit cast[int64](uintVal(cc))
          else:                                         # register index (pre-loaded by premat)
            g.emReg g.plan.planned(cursorToPosition(g.buf[], cc)).r
          skip cc
          if g.lvalStride.hasKey(atPos):
            g.emReg g.lvalStride[atPos]                 # 3-operand form: non-SIB stride scratch
          while cc.hasMore: skip cc
    of DerefC:
      var pointee = g.getType(c)                        # deref result = the pointee type
      var cc = c
      cc.into:
        let pReg = g.plan.planned(cursorToPosition(g.buf[], cc))
        g.ab.tree CastX:
          g.ab.ptrType:
            if pointee.kind == Symbol: g.ab.sym symName(pointee)
            else: g.genTypeBody(pointee)
          g.emReg pReg.r                                # the pointer, by its bound name
        while cc.hasMore: skip cc
    of PatC:                                            # pointer index: (at (cast (aptr E) p) idx)
      let patPos = cursorToPosition(g.buf[], c)
      var elem = g.getType(c)                           # element / pointee type
      g.ab.tree AtX:
        var cc = c
        cc.into:
          let pReg = g.plan.planned(cursorToPosition(g.buf[], cc))
          g.ab.tree CastX:
            g.ab.aptrType:
              if elem.kind == Symbol: g.ab.sym symName(elem)
              else: g.genTypeBody(elem)
            g.emReg pReg.r                              # the pointer, by its bound name
          skip cc                                       # past pointer
          case cc.kind                                  # index
          of IntLit: g.ab.intLit intVal(cc)
          of UIntLit: g.ab.intLit cast[int64](uintVal(cc))
          else:                                         # register index (pre-loaded by premat)
            g.emReg g.plan.planned(cursorToPosition(g.buf[], cc)).r
          skip cc
          if g.lvalStride.hasKey(patPos):
            g.emReg g.lvalStride[patPos]                # 3-operand form: non-SIB stride scratch
          while cc.hasMore: skip cc
    of BaseobjC:
      # `(baseobj BaseType depth lvalue)` — an object→base view. The base sub-object is at
      # offset 0, so the ADDRESS is the inner lvalue's, only the TYPE narrows. A `(deref p)`
      # inner re-emits as `(cast (ptr BaseType) p)` (same pointer, base-typed, so an enclosing
      # `dot` resolves a base field and an `addr` yields `(ptr BaseType)`); any other inner
      # lvalue is emitted transparently (nifasm flattens inherited fields for resolution).
      var cc = c
      cc.into:
        let baseTy = cc; skip cc                          # the base type (a Symbol)
        skip cc                                           # depth
        if cc.kind == TagLit and cc.exprKind == DerefC:
          var dc = cc
          dc.into:
            let pReg = g.plan.planned(cursorToPosition(g.buf[], dc))
            g.ab.tree CastX:
              g.ab.ptrType: g.ab.sym symName(baseTy)
              g.emReg pReg.r
            while dc.hasMore: skip dc
        else:
          g.emLvalAddr2(cc)                               # transparent (inherited fields flatten)
        while cc.hasMore: skip cc
    of AconstrC, OconstrC:
      # A constructor base materialized into `aggtmp<pos>` by `prematLval2`: address it as
      # an ordinary stack-var base.
      let pos = cursorToPosition(g.buf[], c)
      g.ab.sym (synth("aggtmp") & $pos & ".0")
    else: raiseAssert "arkham x64n: emLvalAddr2 expr " & $c.exprKind
  else: raiseAssert "arkham x64n: emLvalAddr2 kind " & $c.kind

proc takeLvalStride*(g: var CodeGen; c: Cursor; atPos: int; asBase = false;
                    hint = NoReg) =
  ## Reserve the non-SIB `(at/pat base idx scratch)` stride scratch from the emit-time
  ## STAGING set (the always-free R11 bridge + free caller-saved), NOT a pool register
  ## the allocator handed out — so it cannot starve when register-homed locals fill the
  ## pool (the x64 trepro `out of registers for an index stride scratch` case). Taken
  ## AFTER the base/index are materialized: they are sealed + bound by then, so the pick
  ## cannot alias them (the Bug-J disjointness invariant — nifasm also rejects
  ## scratch==base at assemble time) and the scratch does not sit reserved, holding
  ## nothing, across a premat recursion that may itself need staging registers (the
  ## `-d:danger` `cmpStringPtrs` "no staging register available for a spill" case: a
  ## spilled `(pat …)` pointer whose own address is a spilled load needs three).
  ## A nested `(at (at …) …)` nests fine: the inner level takes its scratch first and
  ## keeps it sealed, so the outer's pick avoids it. Released by `dropLvalStride`
  ## after the `(mem …)`.
  ##
  ## `asBase`: this `(at)`/`(pat)` is itself the BASE of an enclosing indexed access. x86
  ## allows only ONE index register per memory operand, so even a SIB-valid stride (the
  ## inner dimension of `a[i][j]` whose element size is 1/2/4/8) must materialize the inner
  ## address into a clean base register when its index is a register — else the fold would
  ## carry two index registers (the `(at (at base i) j)` two-register case nifasm rejects).
  if not (g.atNeedsScratch(c) or (asBase and g.atIndexIsReg(c))): return
  # BORROW the CONSUMER's destination register (`lea dst, (at …)` /
  # `mov dst, (mem (at …))`): it is reserved but still empty — the consuming
  # instruction writes it only after reading the address it is computing. Both
  # assemblers fold the stride into the scratch and then address `[scratch]`, so
  # `scratch == dst` is exactly the `lea dst, [dst+disp]` a two-step address
  # computation would emit anyway. Refused when `dst` already carries part of
  # THIS address (a global base leas into the same register — nifasm rejects
  # `scratch == base`).
  #
  # NOT the index register, even though both assemblers document `scratch ==
  # index` as legal: legal there means "the multiply still reads a live index",
  # not "the index is dead afterwards". A materialized index outlives its
  # access — `a[i].f0 = 0; a[i].f1 = 0` reloads `i` once and folds it twice —
  # so `lea idx, [base+idx*16]` leaves the second fold multiplying an ADDRESS.
  if hint != NoReg and not g.lvalUsesReg(c, hint):
    g.lvalStride[atPos] = hint
    g.lvalStrideBorrowed.incl atPos
    return
  let s = g.pickStagingScratch()
  if s == NoReg:
    raiseAssert "arkham x64: no staging register for an (at) stride scratch in proc " &
                g.curProcName & " (asBase=" & $asBase & ", hint=" & $hint & ")" &
                g.stagingCensus(NoReg)
  g.plan.seal s
  g.bindTemp(s, AsmSlot(cls: AInt, size: 8, align: 8))
  g.lvalStride[atPos] = s

proc unbindLvalTemps2*(g: var CodeGen; c: Cursor) =
  ## Release any scratch temp an lvalue's embedded value was loaded into (e.g. a
  ## stack-homed pointer reloaded for a `deref`/`pat`), AFTER the consuming
  ## (mem …)/(lea …) instruction. A reg-homed base sits in its own home (not a temp)
  ## ⇒ no-op. The load/store RESULT temp is separate (the consumer unbinds it).
  if c.kind == Symbol:
    let pos = cursorToPosition(g.buf[], c)
    if g.lvalGlobBase.hasKey(pos):                    # transient global-base staging reg
      let s = g.lvalGlobBase[pos]
      g.unbindTemp(s)
      g.plan.unseal s
      g.lvalGlobBase.del pos
    return
  if c.kind == TagLit:
    case c.exprKind
    of DotC:
      var cc = c
      cc.into:
        g.unbindLvalTemps2(cc)                          # base
        while cc.hasMore: skip cc
    of AtC:
      let atPos = cursorToPosition(g.buf[], c)
      var cc = c
      cc.into:
        g.unbindLvalTemps2(cc); skip cc                 # base
        if cc.kind notin {IntLit, UIntLit}: g.freeExpr(cc)   # register index temp
        while cc.hasMore: skip cc
      g.dropLvalStride(atPos)                            # the non-SIB stride scratch
    of DerefC:
      var cc = c
      cc.into:
        g.freeExpr(cc)                                   # the pointer
        while cc.hasMore: skip cc
    of PatC:
      let patPos = cursorToPosition(g.buf[], c)
      var cc = c
      cc.into:
        g.freeExpr(cc)                                   # the pointer
        skip cc
        if cc.kind notin {IntLit, UIntLit}: g.freeExpr(cc)   # register index temp
        while cc.hasMore: skip cc
      g.dropLvalStride(patPos)                            # the non-SIB stride scratch
    of BaseobjC:                                        # transparent: release the inner lvalue
      var cc = c
      cc.into:
        skip cc; skip cc                               # base type, depth
        g.unbindLvalTemps2(cc)                         # the inner lvalue
        while cc.hasMore: skip cc
    else: discard

proc emMemLval2*(g: var CodeGen; c: Cursor) =
  ## `(mem <address> [disp])` — the ONE place a folded constant displacement is
  ## emitted, so it can only ever appear where nifasm reads it as one: as the second
  ## child of a `mem` node. `emLvalAddr2` stays displacement-free, which is what keeps
  ## a nested `deref` under a `(dot …)`/`(at …)`/`(lea …)` correct by construction.
  ## Pair with `prematLval2(c, foldDisp = true)`.
  g.ab.tree MemX:
    g.emLvalAddr2(c)
    let (_, disp, folded) = g.derefDispSplit(c)
    if folded: g.ab.intLit disp.int64

proc emByteAtImm*(g: var CodeGen; p: Reg; off: int) =
  ## `(mem (at (cast (aptr (u 8)) p) off))` — the byte at `[p + off]` (immediate offset).
  g.ab.tree MemX:
    g.ab.tree AtX:
      g.ab.tree CastX:
        g.ab.aptrType: g.ab.uintType(8)
        g.emReg p
      g.ab.intLit off.int64

proc emWordAt(g: var CodeGen; e: AggrEnd; idx: int) =
  if e.slot.len > 0: g.emWordAtSlot(e.slot, idx * 8)
  else: g.emWordThroughPtr(e.reg, idx)

proc emByteAt*(g: var CodeGen; e: AggrEnd; off: int) =
  if e.slot.len > 0: g.emByteAtSlot(e.slot, off)
  else: g.emByteAtImm(e.reg, off)

proc copyAggr*(g: var CodeGen; dst, src: AggrEnd; size: int; tmp: Reg) =
  ## Copy `size` bytes from `src` to `dst` through the bound scratch `tmp` — 8-byte words
  ## for the aligned bulk, then a sized byte tail. Layout-agnostic and byte-accurate, so it
  ## is TOTAL for any aggregate regardless of field packing. nifasm's sized mem↔reg move
  ## extends a byte load / truncates a byte store, so `tmp` stays a plain `(u 64)`.
  ## (`tmp` and any register end are bound by the caller.)
  ##
  ## MEASURED NEGATIVE RESULT (2026-08-16) — do NOT "optimize" this into 16-byte
  ## `movdqu` chunks while arkham's WRITERS stay word-granular. It was tried (nifasm
  ## kept the `movdqu` instruction): instruction count dropped ~1% across every
  ## nifbench bench, but wall time went +10.7% TOTAL — parse +28%, bif-load +39% —
  ## because a 16-byte load over an aggregate that was just built with 8-byte field
  ## stores cannot STORE-FORWARD (narrow-stores→wide-load always stalls, ~12+ cycles
  ## per hot copy, dwarfing the two saved moves). The benches that copy stable,
  ## long-written data (walk/skim/clone) did win ~3%, but the copy sites are shared,
  ## so there is no static split. gcc -O3 copies aggregates with movdqu profitably
  ## only because it vectorizes the CONSTRUCTION side too, so its wide loads forward
  ## from wide stores. Revisit only together with SIMD-building constructors.
  let words = size div 8
  for i in 0 ..< words:
    g.ab.tree MovX64: (g.emReg tmp; g.emWordAt(src, i))
    g.ab.tree MovX64: (g.emWordAt(dst, i); g.emReg tmp)
  for b in 0 ..< (size - words * 8):                     # sub-word tail, byte by byte
    let off = words * 8 + b
    g.ab.tree MovX64: (g.emReg tmp; g.emByteAt(src, off))
    g.ab.tree MovX64: (g.emByteAt(dst, off); g.emReg tmp)

proc copyAggr*(g: var CodeGen; dst, src: Reg; size: int; tmp: Reg) =
  ## Both ends are addresses in registers — the historical shape.
  g.copyAggr(regEnd(dst), regEnd(src), size, tmp)

proc emWordThroughPtr*(g: var CodeGen; p: Reg; idx: int) =
  ## `(mem (at (cast (aptr (u 64)) p) idx))` — the `idx`-th 8-byte word at `[p]`, typed
  ## `(u 64)`. nifasm scales `idx` by 8, so this is raw `[p + idx*8]` access that
  ## ignores the aggregate's field layout entirely.
  g.ab.tree MemX:
    g.ab.tree AtX:
      g.ab.tree CastX:
        g.ab.aptrType: g.ab.uintType(64)
        g.emReg p
      g.ab.intLit idx.int64

proc emPtrElemMem*(g: var CodeGen; p: Reg; elemTy: Cursor; idx: int) =
  ## `(mem (at (cast (aptr ElemTy) p) idx))` — element `idx` of an array whose first
  ## element is at `[p]`; nifasm scales `idx` by the element size (from ElemTy) and
  ## sizes the access from ElemTy. Used to build an `aconstr` straight into the array
  ## addressed by a pointer (e.g. a global's address) — the array twin of
  ## `emPtrFieldMem`.
  var et = elemTy
  g.ab.tree MemX:
    g.ab.tree AtX:
      g.ab.tree CastX:
        g.ab.aptrType: g.genTypeBody(et)
        g.emReg p
      g.ab.intLit idx.int64

proc regsToStructThroughPtr*(g: var CodeGen; ptrReg: Reg; typeSym: SymId;
                            regs: openArray[Reg]) =
  ## `[ptrReg] ← regs` — marshal a ≤16B aggregate held in `regs` (the by-value ABI
  ## return registers rax:rdx) into the memory `ptrReg` points at. A FULL eightbyte is
  ## a raw `(u 64)` word (handles packed fields); a trailing PARTIAL eightbyte (a
  ## single sub-word field) uses the field-typed access. The through-pointer twin of
  ## `regsToStruct` (which addresses a named stack slot) — used to store an aggregate
  ## call result into a global.
  let byteSize = aggrByteSize(g.prog, typeSym)
  for i in 0 ..< aggrWordCount(g.prog, typeSym):
    if byteSize - i * 8 >= 8:
      g.ab.tree MovX64: (g.emWordThroughPtr(ptrReg, i); g.emReg regs[i])
    else:
      let fn = fieldAtOffset(aggrLayout(g.prog, typeSym), i * 8)
      g.ab.tree MovX64: (g.emPtrFieldMem(ptrReg, typeSym, fn); g.emReg regs[i])

proc marshalAggrFromAddr*(g: var CodeGen; addrReg: Reg; typeSym: SymId;
                         regs: openArray[Reg]) =
  ## `regs ← [addrReg]` — load a ≤16B aggregate at `[addrReg]` into the by-value ABI
  ## argument registers (a FULL eightbyte as a raw `(u 64)` word, a trailing PARTIAL via
  ## the field-typed access). The reverse of `regsToStructThroughPtr`; lets an aggregate
  ## CALL ARGUMENT marshal straight from its address (`aggrAddrInto`) with no copy temp.
  let byteSize = aggrByteSize(g.prog, typeSym)
  for i in 0 ..< aggrWordCount(g.prog, typeSym):
    if byteSize - i * 8 >= 8:
      g.ab.tree MovX64: (g.emReg regs[i]; g.emWordThroughPtr(addrReg, i))
    else:
      let fn = fieldAtOffset(aggrLayout(g.prog, typeSym), i * 8)
      g.ab.tree MovX64: (g.emReg regs[i]; g.emPtrFieldMem(addrReg, typeSym, fn))

proc emLvalFieldMem*(g: var CodeGen; lhs: Cursor; field: string) =
  ## `(mem (dot <lvalue address> field))` — a field within the aggregate addressed by
  ## the lvalue `lhs` (a `dot`/`at`/`deref` chain). The lvalue's embedded value
  ## registers must already be materialized (`prematLval2`).
  g.ab.tree MemX:
    g.ab.tree DotX:
      g.emLvalAddr2(lhs)
      g.ab.sym field

proc bindLvalGlobalBases*(g: var CodeGen; c: Cursor; bound: var seq[Reg]) =
  ## Bind the pre-assigned address register of every global base in lvalue `c`, so
  ## `prematLval2` leas `&global` into a BOUND register before the `(mem …)` tree
  ## opens (emReg rejects an unbound scratch-pool reg). The scalar load reuses its
  ## result temp for this (see emitMemLoad2's "bind first"); an aggregate copy has
  ## no result reg, so it binds the base regs explicitly. Recurses only into the
  ## BASE (first child) of a dot/at/deref — not the index/field.
  if c.kind == Symbol:
    let loc = g.plan.planned(cursorToPosition(g.buf[], c))
    if loc.kind == InReg and loc.isTemp and not g.rb.isBoundTemp(loc.r) and
       g.plan.locationOfSym(symName(c), cursorToPosition(g.buf[], c)).kind == NoLoc:
      # only an UNBOUND base reg (else the caller already bound it — e.g. `emitAddr2`
      # reuses its bound result reg for the global base; rebinding would clobber it).
      g.bindTemp(loc.r, ScalarSlot)
      bound.add loc.r
  elif c.kind == TagLit and c.exprKind in {AtC, DotC, DerefC, PatC}:
    var cc = c
    cc.into:
      g.bindLvalGlobalBases(cc, bound); skip cc          # the base only
      while cc.hasMore: skip cc

proc emLvalElemMem*(g: var CodeGen; lhs: Cursor; idx: int) =
  ## `(mem (at <lvalue address> idx))` — element `idx` of the array addressed by `lhs`.
  ## The lvalue's embedded value registers must already be materialized (`prematLval2`).
  g.ab.tree MemX:
    g.ab.tree AtX:
      g.emLvalAddr2(lhs)
      g.ab.intLit idx

proc fcvtU2F*(g: var CodeGen; d: FReg; s: Reg; bits: int) =
  ## UNSIGNED 64-bit → float. `cvtsi2sd` reads its GPR as a SIGNED 64-bit value,
  ## and SSE2 has no unsigned counterpart, so a source with bit 63 set would
  ## convert to a negative double (`float(0xFFFF_FFFF_FFFF_FFFF'u64)` came out
  ## -1.0). Split on that bit:
  ##
  ##   * clear ⇒ the value is its own signed reading; one `cvtsi2sd`.
  ##   * set ⇒ halve it, convert, and double the result back. The halving is
  ##     ROUND-TO-ODD (`(v shr 1) or (v and 1)`), which keeps the discarded low
  ##     bit as a sticky bit so `cvtsi2sd`'s own rounding cannot round twice —
  ##     a plain `shr` would make e.g. 2^64-1 come out as 2^64 exactly.
  ##
  ## `s` is only READ: it may be a live local's home register.
  let lBig = g.freshLabel()
  let lDone = g.freshLabel()
  g.cmpZero s
  g.emJcc(JlX64, lBig)                             # bit 63 set ⇒ ≥ 2^63 unsigned
  g.fcvtI2F(d, s, bits)
  g.emJmp lDone
  g.emLab lBig
  let half = g.pickStagingSealed("an unsigned int→float halving", ScalarSlot)
  let odd = g.pickStagingSealed("an unsigned int→float sticky bit", ScalarSlot)
  g.movReg(half, s)
  g.binImm(ShrX64, half, 1)
  g.movReg(odd, s)
  g.binImm(AndX64, odd, 1)
  g.binReg(OrX64, half, odd)
  g.fcvtI2F(d, half, bits)
  g.fbin(AddssX64, AddsdX64, d, d, bits)           # ×2 undoes the halving
  g.giveBack odd
  g.giveBack half
  g.emLab lDone

proc emitLvalWalk*(g: var CodeGen; n: var Cursor; globBase: Location; isStore: bool;
                  heldBase = false) =
  ## FUSED port of the allocator's `allocLvalue2`: walk an lvalue subtree,
  ## deciding its embedded values' locations into the `plan.locs` memo — the
  ## registers `prematLval2` materializes into and `emLvalAddr2` reads. Pure
  ## pick-and-record: NO emission here. Advances `n` past the whole lvalue.
  ##
  ## `heldBase` says an enclosing `(at …)`/`(pat …)` has an INDEX that CALLS (a
  ## bounds check, typically): the base is materialized before that call and
  ## read back after it, so its scratch must be a callee-saved survivor rather
  ## than a volatile the call would clobber (075b051's fix, fused twin).
  case n.kind
  of Symbol:
    let nm = symName(n)
    if g.plan.locationOfSym(nm, cursorToPosition(g.buf[], n)).kind == NoLoc:         # a module-level global aggregate base
      let pos = cursorToPosition(g.buf[], n)
      if globBase.kind == InReg:
        g.plan.planAtEmitTime(pos, globBase)
      elif not isStore and not heldBase:
        # transient global base for a LOAD: `prematLval2` sources the address
        # from emit-time staging (the R11 bridge) — leave the position
        # unresolved as the marker.
        g.plan.planAtEmitTime(pos, dontCare)
      else:
        g.plan.planAtEmitTime(pos, g.takeHeld("a global base address"))
    inc n                                            # stack-var / pointer / global base name
  of TagLit:
    case n.exprKind
    of DotC:
      n.into:
        g.emitLvalWalk(n, globBase, isStore, heldBase) # base (a stack var, deref, or global)
        while n.hasMore: skip n                      # field name (+ any extras)
    of DerefC:
      n.into:
        g.getExpr(n, heldBase, "a deref base held across an index call")  # the pointer
        while n.hasMore: skip n
    of AtC:
      n.into:
        # Peek at the index BEFORE deciding the base: a calling index (a bounds
        # check) clobbers the volatiles between the base's materialization and
        # its use, so the base subtree must take survivors.
        var idxPeek = n; skip idxPeek
        let held = heldBase or subtreeHasCallE(idxPeek)
        g.emitLvalWalk(n, globBase, isStore, held)   # base (stack array, deref, or global)
        if n.kind in {IntLit, UIntLit}: skip n       # immediate index — folds, no scratch
        else: g.getExpr(n, false, "")                # register index (folds via scale)
        while n.hasMore: skip n
    of PatC:
      n.into:
        var idxPeek = n; skip idxPeek                # same base-vs-calling-index hazard
        let held = heldBase or subtreeHasCallE(idxPeek)
        g.getExpr(n, held, "a pat base held across an index call")        # the pointer
        if n.kind in {IntLit, UIntLit}: skip n       # immediate index
        else: g.getExpr(n, false, "")
        while n.hasMore: skip n
    of BaseobjC:                                     # `(baseobj BaseT depth lvalue)` — transparent
      n.into:
        skip n                                       # base type
        skip n                                       # depth
        g.emitLvalWalk(n, globBase, isStore, heldBase) # the inner lvalue
        while n.hasMore: skip n
    of AconstrC, OconstrC:
      # A constructor used as an lvalue base (`[a,b][i]`): nothing to decide
      # here — `prematLval2` builds it into its `aggtmp<pos>` slot via the
      # (fused) `genStore2`, whose single-use temps are decided there.
      skip n
    else:
      raiseAssert "arkham x64n: computed lvalue base not supported: " & $n.exprKind
  else:
    inc n

proc emitLvalue2*(g: var CodeGen; c: Cursor; globBase = dontCare; isStore = false) =
  var n = c
  g.emitLvalWalk(n, globBase, isStore)
