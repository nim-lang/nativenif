
import std / [tables, sets, streams, os, osproc, strutils, algorithm]
import nifcore, nifcoreparse, nifmodules
import "../../../nimony/src/lib" / [nifreader, symparser]
import tags, model, tagconv, tagpool
import buffers, relocs, x86, arm64, elf, macho, pe
from thumb2 import nil   # qualified: Nim conflates `emitBL` (arm64) with `emitBl`
                         # (thumb2), and `Register` would clash three ways
from elf32 import nil        # qualified: `elf32` repeats ET_EXEC/PT_LOAD/PF_*
                                 # under 32-bit types, which would shadow `elf`'s
import dwarf, tracetable
import sem, slots
import decls

const
  WindowsKernelDll = "kernel32.dll"
    ## The implicit import library of a Windows image — the one arkham binds against.

  ListingTextCap = 300
    ## `--listing` renders each instruction node as NIF; a compound node (a whole
    ## `(ite …)`, a `(prepare …)` with every argument) can be enormous and its
    ## deeper rows carry the detail anyway, so the text is capped.

  WinShadowSpace = 32
    ## Win64 makes the CALLER reserve 32 bytes at the bottom of the outgoing argument
    ## area that the callee may spill its four register arguments into, whether or not
    ## it has four parameters. So a call's stack arguments start at `[rsp+32]`, not
    ## `[rsp+0]`, and even a no-stack-argument call occupies 32 bytes of frame.
    ##
    ## Reserved for EVERY call in a `win_x64` image, not only the ones that leave it.
    ## arkham's own procs never touch the area (their convention is SysV-shaped —
    ## see arkham's `generateX64`), so those 32 bytes are pure frame waste there; but
    ## a call THROUGH a function pointer cannot be told apart from an internal one at
    ## this level — `winlean` reaches every one of its `dynlib` imports that way — and
    ## reserving uniformly is what makes the layout agree on both sides regardless.
    ## Mirrored in arkham's `machine_x64.WinShadowSpace`.

var asmTags: TagPool = createAsmTagPool()
  ## The one seeded tag pool; `assemble` re-creates it per run is unnecessary —
  ## a single process assembles one program.

proc tag(n: Cursor): TagEnum = cast[TagEnum](uint32(resolvedTagId(n)))
  ## `resolvedTagId`, not `cursorTagId`: asm-NIF's vocabulary overflows the
  ## 9-bit tag field, so the mnemonics past it carry their id in a leading child
  ## (see `tagpool`). Everything downstream — `tagToX64Inst`, `tagToA64Inst`,
  ## `tagToNifasmDecl`, every `n.tag == …TagId` — reads the same either way.

proc nodeRepr(n: Cursor): string =
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

proc infoStr(n: Cursor): string =
  let li = n.rawLineInfo
  if li.isValid:
    result = n.lineInfoFile & "(" & $li.line & ", " & $li.col & ")"
  else:
    result = "???"

var gCurProc = ""
var gLenient = false
  ## The proc currently being assembled. arkham's asm-NIF carries no line info, so
  ## `infoStr` degrades to `???` and a bare type error names nothing you can act on;
  ## the proc's mangled symbol pins it to one module and one routine.

proc error(msg: string; n: Cursor) =
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

proc typeError(want, got: Type; n: Cursor) =
  error("Type mismatch: expected " & $want & ", got " & $got, n)

proc addrWidthMove(a, b: Type): bool {.inline.} =
  ## A pointer — a function pointer (`ProcT`), a data pointer (`PtrT`/`AptrT`) — is an
  ## 8-byte address. Moving it to/from a general 64-bit register, an integer, or
  ## another pointer is a plain address move: loading an indirect-call target or a
  ## pointer field, storing a function's address into a fn-ptr slot, or — pervasive in
  ## arkham's value core — holding a pointer value in a generic `i64` scalar register.
  ## All representationally identical (8 bytes), so accept it in either direction. (A
  ## genuinely narrowing access stays caught by the sized memory-access path.)
  if a == nil or b == nil: return false
  const PtrLike = {ProcT, PtrT, AptrT}
  const AddrLike = {ProcT, PtrT, AptrT, IntT, UIntT}
  (a.kind in PtrLike and b.kind in AddrLike) or (b.kind in PtrLike and a.kind in AddrLike)

proc litFitsWidth(v: int64; bits: int): bool {.inline.} =
  ## Does integer literal `v` fit a `bits`-wide destination, read as either
  ## signed or unsigned? (`0..2^bits-1` ∪ `-2^(bits-1)..-1`.) Both readings are
  ## the same bit pattern in the same register, and which one a value "is" is the
  ## instruction's business, not the literal's.
  if bits >= 64: return true
  v >= -(1'i64 shl (bits - 1)) and v <= (1'i64 shl bits) - 1

proc movCompatible(want, got: Type): bool =
  ## Type rule for `mov`: strict compatibility, OR a *widening* integer move —
  ## a smaller integer into a larger register (a safe extending move/load).
  ## Narrowing or a kind change (int↔ptr/float) is still rejected.
  if compatible(want, got): return true
  if addrWidthMove(want, got): return true
  # A `mov` to/from a stack slot named directly (`(mov stackvar value)` stores,
  # `(mov reg stackvar)` loads) targets the slot's *content* type, so re-check against
  # the unwrapped element type on either side. (Previously the register operand was
  # always a raw register — lenient `RegisterT`, compatible with any slot — but a
  # `rebind`-bound scratch carries its concrete type, e.g. `(i 64)`.)
  # Re-run `addrWidthMove` after the unwrap too: a caller-save spill of a pointer
  # (`(mov (s)(ptr T) slot, i64-bound-name)` / the restore) is an address-width move
  # through a `StackOffT` wrapper, and the pre-unwrap check sees `StackOffT` which
  # is neither PtrLike nor AddrLike.
  var w = want
  var g = got
  if w.kind == StackOffT: w = w.offType
  if g.kind == StackOffT: g = g.offType
  if compatible(w, g): return true
  if addrWidthMove(w, g): return true
  if w.kind in {IntT, UIntT} and g.kind == IntLitT:
    # A literal carries no width of its own — `parseOperand` types every one as
    # `(lit 64)` — so judge it by its VALUE: it fits when the destination width
    # holds the bit pattern under EITHER reading. `(u 32) ← 2400959708`
    # (0x8F1BBCDC, a SHA-1 round constant) is a plain 32-bit store; so is
    # `(u 32) ← -1`. Only a literal too wide for the destination is narrowing.
    return litFitsWidth(g.litVal, w.bits)
  if w.kind in {IntT, UIntT} and g.kind in {IntT, UIntT}:
    return g.bits <= w.bits
  result = false

proc getInt(n: Cursor): int64 =
  if n.kind == IntLit:
    result = n.intVal
  else:
    error("Expected integer literal", n)

proc parseSlotAlign(n: var Cursor): int =
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

proc normScalarBits(bits: int64): int =
  ## Leng encodes the architecture-width `int`/`uint`/`char` (and other
  ## native-word scalars) as a NON-POSITIVE bit count — `(i -1)` is the platform
  ## `int`. arkham resolves this to the word size (`slots.scalarSlot`: `bits <= 0`
  ## ⇒ 8 bytes); nifasm must agree or a `(i -1)` field is sized 0 and every later
  ## field's offset collapses (e.g. a ref payload's hidden header `(fld :r (i -1))`
  ## would put the real first field at offset 0, so `obj.field` reads the header).
  ## The width comes from the `(arch …)` pragma via `setAsmWordSize`, so a 32-bit
  ## target resolves it to 32 — see `asmWordBits`.
  if bits > 0: int(bits) else: asmWordBits()

template symName(n: Cursor): string =
  ## The symbol's fully-qualified name. The NIF reader already completes the
  ## self-module trailing-dot compression (using each module's own suffix, set
  ## from its filename), so the interned string is module-correct as-is.
  nifcore.symName(n)

proc getSym(n: Cursor): string =
  case n.kind
  of Symbol:
    result = symName(n)
  else:
    error("Expected symbol", n)

proc getSymId(n: Cursor): SymId =
  ## The interned identity of a `Symbol`/`SymbolDef` token — a key into the scope
  ## without materializing (and re-hashing) the qualified-name string. Valid across
  ## modules because every cursor interns into the one shared pool (`ctx.pool`).
  case n.kind
  of Symbol, SymbolDef:
    result = symId(n)
  else:
    error("Expected symbol", n)
    result = SymId(0)

proc getSymDef(n: var Cursor): string =
  if n.kind != SymbolDef:
    error("Expected symbol definition", n)
  result = symName(n)
  skip n

proc getStr(n: Cursor): string =
  if n.kind == StrLit:
    result = n.strVal
  else:
    error("Expected string literal", n)

proc isIntegerType(t: Type): bool =
  ## Check if type is an integer type (int, uint, literal) or a register (which is untyped)
  t.kind in {TypeKind.IntT, TypeKind.UIntT, TypeKind.IntLitT, TypeKind.RegisterT}

proc isFloatType(t: Type): bool =
  ## Check if type is a floating point type
  t.kind == TypeKind.FloatT

proc canDoIntegerArithmetic(t: Type): bool =
  ## May `t` be an operand of `add`/`sub`/`neg`? Integers, integer literals and raw
  ## (untyped) registers — no pointer of any kind.
  ##
  ## `(aptr T)` used to be admitted here as "pointer arithmetic". It is not a legal
  ## Leng form: an `add` says nothing about whether the offset counts BYTES or
  ## ELEMENTS, and the two backends answered differently — nifasm emitted a plain
  ## machine `add` (bytes) while lengc's C output read the same node as scaled C
  ## pointer arithmetic (elements). Offsetting an array pointer is `(at base index)`,
  ## which takes the element type and therefore has one meaning; raw byte work casts
  ## to an integer and back. arkham rejects such a node before it ever gets here
  ## (`checkArithResultType`); this is the assembler's own backstop, and it also
  ## covers hand-written asm-NIF.
  t.kind in {TypeKind.IntT, TypeKind.UIntT, TypeKind.IntLitT, TypeKind.RegisterT}

proc canCompare(t: Type): bool =
  ## Check if a type may be a `cmp` operand. A superset of integer arithmetic:
  ## any pointer (a comparison, not arithmetic) and — crucially — `bool`, since a
  ## bool is a 0/1 integer and `cmp reg, 0` is the canonical "if bool" test. This is
  ## deliberately SEPARATE from `canDoIntegerArithmetic` (which add/sub share and
  ## must stay strict — adding/subtracting bools is nonsense).
  t.kind in {TypeKind.IntT, TypeKind.UIntT, TypeKind.IntLitT,
             TypeKind.PtrT, TypeKind.AptrT, TypeKind.RegisterT, TypeKind.BoolT,
             TypeKind.NilT}  # `cmp ptr, nil` / `cmp nil, ptr` null tests

proc canDoBitwiseOps(t: Type): bool =
  ## May `t` be an operand of `and`/`or`/`xor`/`not`? Integers, literals, raw
  ## registers — and `bool`, for the same reason `canCompare` admits it: a bool is
  ## an 8-bit 0/1 integer, and masking one is meaningful. `and reg, 1` after a
  ## `setcc` is what ESTABLISHES the 0/1 invariant (the byte write leaves the rest
  ## of the register alone), so rejecting it rejected the very sequence that makes a
  ## bool a bool — `arc/t24764` and 74 other native tests died on it.
  ##
  ## Pointers stay out: there is no bit pattern of a pointer a code generator has
  ## business masking without saying so through a cast.
  t.kind in {TypeKind.IntT, TypeKind.UIntT, TypeKind.IntLitT, TypeKind.RegisterT,
             TypeKind.BoolT}

proc canExchange(t: Type): bool =
  ## Check if a type may be an `xchg` operand: any register-sized scalar — integer
  ## OR pointer. `xchg` swaps 8 bytes irrespective of the logical type, and an atomic
  ## pointer exchange (lock-free list head swap) is a legitimate, common use. Like
  ## `canCompare`, this is SEPARATE from the arithmetic check (which stays strict);
  ## unlike it, `bool` is excluded (swapping a bool through a pointer is nonsense).
  t.kind in {TypeKind.IntT, TypeKind.UIntT, TypeKind.IntLitT,
             TypeKind.PtrT, TypeKind.AptrT, TypeKind.RegisterT}


proc tagToRegister(t: TagEnum; n: Cursor): x86.Register =
  ## Convert a TagEnum to an x86 Register (for register binding tracking)
  let regTag = tagToX64Reg(t)
  result =
    case regTag
    of RaxR, R0R: x86.RAX
    of RcxR, R2R: x86.RCX
    of RdxR, R3R: x86.RDX
    of RbxR, R1R: x86.RBX
    of RspR, R7R: x86.RSP
    of RbpR, R6R: x86.RBP
    of RsiR, R4R: x86.RSI
    of RdiR, R5R: x86.RDI
    of R8R: x86.R8
    of R9R: x86.R9
    of R10R: x86.R10
    of R11R: x86.R11
    of R12R: x86.R12
    of R13R: x86.R13
    of R14R: x86.R14
    of R15R: x86.R15
    else:
      error("Expected GPR register, got: " & $t, n)
      x86.RAX

proc parseRegister(n: var Cursor): x86.Register =
  result = tagToRegister(n.tag, n)
  inc n

proc isXmmTag(n: Cursor): bool {.inline.} =
  n.kind == TagLit and n.tag >= Xmm0TagId and n.tag <= Xmm15TagId

proc isXmmTagEnum(t: TagEnum): bool {.inline.} =
  t >= Xmm0TagId and t <= Xmm15TagId

proc tagToXmm(t: TagEnum): x86.XmmRegister {.inline.} =
  x86.XmmRegister(ord(t) - ord(Xmm0TagId))

proc parseXmm(n: var Cursor): x86.XmmRegister =
  ## Parse a *raw* `(xmmN)` SSE register operand (N in 0..15). Used only where a
  ## bare register is required (the `rebind`/`withreg` target). Operand reads in the
  ## scalar-float instructions go through `parseXmmOperand`, which also accepts a
  ## bound name and rejects a raw use of a bound register.
  if not isXmmTag(n):
    error("expected xmm register", n)
  result = x86.XmmRegister(ord(n.tag) - ord(Xmm0TagId))
  inc n

const MainModuleName* = ""  # Special name for main module

type
  LoadedModule = ref object
    ## A loaded module. The MAIN module is parsed whole into `buf` (local symbols
    ## carry a `declStart` token position into it). A FOREIGN module is opened
    ## lazily through the shared `nifmodules.ForeignModule`: only its embedded NIF
    ## `.index` (symbol → byte offset) is read up front; declarations are parsed
    ## one at a time on demand, by following a referenced name (nominal typing).
    ## The foreign handle keeps each lazily-parsed decl tree alive so the Cursors
    ## into it stay valid. (A `ref` so a handle stays valid even if `ctx.modules`
    ## rehashes while a decl body recursively pulls in further foreign modules.)
    buf: TokenBuf                          # whole-module tree (main module only)
    foreign: ForeignModule                 # lazy per-symbol loader (foreign only)
    loaded: bool  # True if already loaded into scope

  Arch = enum
    X64        # Linux x86-64 (ELF)
    LinuxA64   # Linux ARM64 (ELF)
    A64        # macOS ARM64 (Mach-O)
    WinX64     # Windows x86-64 (PE)
    WinA64     # Windows ARM64 (PE)
    CortexM    # Bare-metal ARMv7E-M / Cortex-M4 (ELF32 firmware image, no OS)

  ImportedLib = object
    name: string     # Library path (e.g. "/usr/lib/libSystem.B.dylib")
    ordinal: int     # Library ordinal (1-based index)

  ExtProcInfo = object
    name: string     # Internal name
    extName: string  # External symbol name (e.g. "_write")
    libOrdinal: int  # Which library (1-based)
    gotSlot: int     # GOT slot index
    stubOffset: int  # Offset in stub section
    callSites: seq[int]  # Positions of BL instructions that call this proc

  CallContextState = enum
    Disabled, NormalCall, ExternalCall

  CallContext = object          ## Context for a `prepare` block - tracks call setup state
    state: CallContextState
    callEmitted: bool           # True after (call), (tailcall) or (extcall)
    isTailcall: bool            # the marker was `(tailcall)`: control does not come
                                # back, so there is no result to bind
    target: string              # Target proc/symbol name (a qualified name whose
                                # module suffix `lookupWithAutoImport` parses — string)
    typ: Type                   # ProcT type (contains params, results, clobbers)
    extProcIdx: int             # Index into extProcs for external calls
    argsSet: HashSet[SymId]    # Arguments assigned (keyed by `Param.name`, an interned id)
    resultsSet: HashSet[SymId] # Results bound (keyed by `Param.name`, an interned id)
    stackArgSize: int           # Computed size of stack arguments (csize), INCLUDING
                                # `stackArgBase` — it is what the frame must reserve
    stackArgBase: int           # Byte offset of the FIRST stack argument within the
                                # outgoing area: 0 normally, `WinShadowSpace` for a
                                # Win64 `extproc` call. Added to every `(arg pN)`
                                # offset, so caller and callee agree on where the
                                # 5th+ argument lives
    indirect: bool              # Target is a function-pointer variable: `typ` is its
                                # proctype signature and `(call)` is an indirect call
                                # through the loaded pointer (vs a direct `call rel32`)
    isSyscall: bool             # Target is a `syproc`: the invocation marker is
                                # `(syscall)`/`(svc)` (inlined kernel trap, no `call`),
                                # and `syscallNr` is loaded into rax/x8 before it
    syscallNr: int

  ListingRow = object
    ## One `genInst` call: the asm-NIF instruction node and the `.text` byte range
    ## it produced. `--listing:FILE` writes these after branch relaxation, so the
    ## positions are the ones in the finished image — which is what makes an
    ## execution profile joinable to the SOURCE construct (and, because arkham
    ## renders a bound register by its variable name, to the variable) rather than
    ## to a bare register number.
    start, stop: int    # `.text` byte range [start, stop)
    depth: int          # `listDepth` at this node; deeper = nearer the machine
    procName: string
    text: string        # the node, rendered as NIF (capped, see ListingTextCap)

  GenContext = object
    scope: Scope        # Current (possibly proc-local) lexical scope
    rootScope: Scope    # Module/global scope; foreign symbols are defined here so
                        # they persist past the proc that first referenced them
                        # (processReachableSymbols looks them up to emit bodies).
    buf: relocs.Buffer  # Code buffer (.text section) for x64
    bssBuf: relocs.Buffer  # BSS buffer (.bss section) for zero-initialized global variables
    arch: Arch
    emitObj: bool       # `--emit-obj`: write a relocatable MH_OBJECT for the system
                        # linker (foreign `.o`/framework linking) instead of a
                        # standalone executable. Mach-O / arm64 only for now.
    symMap: bool        # `--symmap`: dump each generated proc's vaddr to stderr
    lenient: bool       # current proc carries the `(lenient)` pragma
    listing: bool       # `--listing:FILE`: record one row per asm-NIF instruction node
    listingPath: string # where to write it
    debugInfo: bool     # emit `.symtab` + `.eh_frame` (default on). Both are
                        # non-`SHF_ALLOC` and outside every PT_LOAD, so they change
                        # neither the loaded image nor its behaviour — only the
                        # file size — and they are what lets a debugger name and
                        # unwind frames in code that keeps no frame pointer.
    listDepth: int      # nesting depth of the current `genInst` (a compound node such as
                        # `(ite …)`/`(loop …)` recurses); the DEEPEST row covering a byte
                        # is the instruction that actually emitted it
    listRows: seq[ListingRow]
    procName: string
    callContext: CallContext # Current call context
    clobbered: set[x86.Register] # Registers clobbered in current flow (x64 only)
    clobberedA64: set[arm64.Register]  # AArch64 counterpart: caller-saved registers a
                        # `(call)`/`(extcall)` destroyed on the current control-flow
                        # path. Reading a register-bound local that lives in one of
                        # these (a value the call silently overwrote) is rejected — the
                        # call-safety guarantee. Cleared when the register is rewritten;
                        # merged across `ite` branches.
    slots: SlotManager
    ssizePatches: seq[tuple[pos: int; pad: int]]
    unwind: seq[ProcUnwind]       # per-proc name + code range + prologue CFI states,
                                  # for `.symtab` and `.eh_frame` (see dwarf.nim). Grown
                                  # by `pass2Proc`; every position in it is remapped by
                                  # the post-emission layout passes, exactly like
                                  # `gvarSites`.
    inPrologue: bool              # still inside the current proc's prologue: the run of
                                  # pushes / frame `sub` whose CFA effects the FDE records.
                                  # `genInst` clears it at the first instruction that emits
                                  # code and is not one of those (a zero-byte node — a slot
                                  # declaration, a `kill` — is transparent).
    prologueOp: bool              # the instruction just dispatched recorded a CFI step
    cfaOff: int32                 # CFA offset in effect at the current point of the prologue
    reservedArgArea: int          # AArch64 fixed-frame: bytes reserved at the frame bottom
                                  # for the largest outgoing stack-argument area (see
                                  # scanStackArgArea). Locals sit above it; the caller writes
                                  # `(mem (sp)(arg pN))` with no per-call `sub sp`.
    csizePatches: seq[(int, int)] # (position, callStackDepth) for csize patches
    gvarSites: seq[(int, Symbol)] # (adrp position in .text, gvar symbol) for adrp+add patching
    tlvSites: seq[(int, Symbol)]  # (adrp position in .text, tvar symbol) for TLV descriptor adrp+add patching (arm64/macOS)
    tlvSyms: seq[Symbol]          # thread-local vars in descriptor order (arm64/macOS); sym.offset = descriptor index, sym.size = byte offset within the per-thread region
    tlvData: seq[byte]            # the __thread_data init template (concatenated per-thread initial values, arm64/macOS)
    tlsOffset: int  # Current TLS offset for thread-local variables (x86)
    bssOffset: int  # Current offset in .bss section
    modules: Table[string, LoadedModule]  # Cache of loaded foreign modules
    pool: Pool          # The main module's literal/symbol pool. Foreign decls are
                        # interned into it too (getDecl is passed `ctx.pool`), so every
                        # cursor's `symId` is a valid key in this one pool and the scope
                        # can be keyed by `SymId` instead of the qualified-name string.
    baseDir: string  # Base directory for finding module files
    thisModule: string  # The module being assembled (symbol suffix of the main file);
                        # a `name.0.<thisModule>` reference is local, not foreign
    regBindings: Table[x86.Register, string]  # Maps registers to variable names they're bound to (x64 only)
    mRegBindings: Table[thumb2.Register, string]
                        # Cortex-M counterpart of `regBindings`: which Thumb register
                        # currently hosts a named local, so a raw `(r4)` use of a bound
                        # register is rejected as the silent clobber it is.
    clobberedM: set[thumb2.Register]
                        # Cortex-M counterpart of `clobberedA64`: caller-saved registers
                        # a call destroyed, so reading one before rewriting it is an error.
    mFRegBindings: Table[thumb2.FloatRegister, string]
                        # The FPv4-SP twin of `mRegBindings`: which s-register hosts a
                        # named float local or scratch temp.
    a64RegBindings: Table[arm64.Register, string]  # AArch64 counterpart of `regBindings`:
                        # which physical x-register currently hosts which variable name. A
                        # raw `(xN)` use of a bound register is rejected (use the name);
                        # `rebind`/`withreg` (re)bind it, killing the prior tenant.
    xmmBindings: Table[x86.XmmRegister, string]  # SSE/float counterpart of `regBindings`
                        # (x64 only): which xmm register currently hosts which float
                        # variable name. A raw `(xmmN)` use of a bound register is rejected;
                        # `rebind`/`withreg` with a float type (re)bind it. Reset per proc.
    a64FRegBindings: Table[arm64.FloatRegister, string]  # SIMD/fp counterpart of
                        # `a64RegBindings` (arm64 only): which v-register currently hosts
                        # which float variable name. A raw `(dN)`/`(sN)` use of a bound
                        # register is rejected; `rebind`/`withreg` with a float type
                        # (re)bind it. The precision (s/d) is recovered from the bound
                        # symbol's type. Reset per proc.
    # Dynamic linking
    imports: seq[ImportedLib]  # Imported libraries
    extProcs: seq[ExtProcInfo]  # External procs to bind
    gotSlotCount: int  # Number of GOT slots allocated
    # Module system / dead code elimination
    pendingSymbols: seq[string]  # Symbols pending code generation
    generatedSymbols: HashSet[string]  # Symbols already generated
    dedupTable: Table[string, string]  # Maps dedup key to canonical symbol name
    definedLabels: HashSet[int]  # LabelIds of *local* labels already defined in the
                        # current proc (populated by (lab …), cleared per proc). A
                        # `jmp`/`jcc`/`b`/`bcc` whose target is in here is a BACKWARD
                        # jump — forbidden: back-edges must be expressed as (loop), so
                        # every emitted control-flow branch stays forward. The internal
                        # loop back-edge is emitted via emitJmp/emitB directly (it never
                        # passes through the instruction handlers), so it is exempt.
    # Thread-local storage (x86-64). nifasm owns the unified per-thread block
    # `arkham.tls.0` (sized for ALL bundled modules' tvars) and synthesizes the
    # entry prologue that points FS at it (`arch_prctl`). Nim thread-locals have no
    # initializers, so the block is just zeroed `.bss`.
    tlsBlockSym: Symbol          # the synthetic `arkham.tls.0` gvar (FS base block)
    # The runtime stack-trace table (`doc/tracetable.md`): the same per-proc facts
    # `.eh_frame` carries, in a form the RUNNING PROGRAM can read — arkham lowers the
    # `traceTable` intrinsic to `lea D, arkham.traceinfo.0`, and `lib/std/stacktraces`
    # walks the stack with it. It is deliberately NOT gated on `debugInfo`: that flag
    # governs what a debugger reads from the file, this is a program feature, and a
    # program that asks for it must get it. Emitted only when something references
    # the symbol, so a program that never calls `getStackTrace` pays nothing.
    traceSym: Symbol             # the synthetic `arkham.traceinfo.0` label
    traceLabel: LabelId          # its label in `buf` — defined where the table lands
    traceUsed: bool              # something referenced it, so `appendTraceTable` runs
    entrySym: Symbol             # the entry proc (`_start`/`main.0`) — prologue jumps here
    entryStubOffset: int          # .text offset of the synthesized ELF entry stub, or -1.
                                  # x86-64: the FS-setup prologue (setupTls); AArch64:
                                  # the argc/argv/envp prologue (setupLinuxA64Entry).
                                  # Both tail-jump to `entrySym`.
    winEntryOffset: int          # .text offset of the synthesized PE entry stub, or -1
                                 # (see setupWinEntry — the Windows counterpart of the
                                 # FS-setup prologue: it supplies `main`'s arguments,
                                 # which the OS does not put anywhere it can find them)
    # A gvar with a compile-time constant scalar initializer is laid out as static
    # data: arkham emits its bits as the gvar value, and these are written into the
    # (writable) `.bss` image on disk so the slot starts with that value (correct in
    # a bundle, where a foreign module's entry-time initializer never runs).
    bssInits: seq[tuple[off: int64, val: int64, size: int]]  # (.bss byte offset, value, size)
    # The same, for a THREAD-LOCAL's literal initializer, keyed by the tvar's
    # displacement inside the unified block. The block's own `.bss` offset is only
    # known once every tvar has one (`setupTls`), which is where these fold into
    # `bssInits`. x86-64 only — macOS/arm64 bakes a tvar initializer into the
    # `__thread_data` template instead (see `generateSymbol`).
    tlsInits: seq[tuple[off: int64, val: int64, size: int]]
    # A gvar whose initializer is a *symbol address* (e.g. a function-pointer hook
    # like `gExitFlush = nimNoopFlush`): the target's absolute vaddr isn't known
    # until layout, so record (slot offset, target symbol) and bake the resolved
    # address into the `.bss` image in `writeElf` (after `finalize`). Without this
    # the slot stays zero and an indirect `call` through it jumps to address 0.
    bssSymInits: seq[tuple[off: int64, sym: Symbol, size: int]]  # (.bss byte offset, target symbol, size)
    # A `const` read-only data blob (e.g. a vtable/RTTI table) with fields that are
    # *symbol addresses* (a pointer to another const, or a proc address). The blob
    # lives in `.text` at its rodata label; the target's vaddr isn't known until
    # layout, so record (rodata label id, byte offset within the blob, target
    # symbol) and bake the resolved address into `code` in `writeElf`.
    rodataSymInits: seq[tuple[labelId: int, blobOff: int, sym: Symbol, size: int]]
    # Mach-O counterpart of `rodataSymInits` for a `dataConst` blob (one that lives
    # in writable __DATA, not __TEXT): the blob is rebased by dyld, so we record the
    # owning const, the byte offset of the pointer field within it, and the target
    # symbol. At `writeMachO` time these become (`__DATA` field offset, target vaddr)
    # pairs: the target's preferred vaddr is baked in and a dyld rebase opcode slides
    # it. Targets in __TEXT and __DATA are both supported.
    rodataRebases: seq[tuple[owner: Symbol, blobOff: int, target: Symbol]]

  OperandKind = enum
    okReg       # Register operand
    okImm       # Immediate value
    okMem       # Memory operand
    okSsize     # Stack size placeholder (patched later)
    okCsize     # Call stack argument size
    okArg       # Argument reference in prepare block
    okLabel     # Label reference

  Operand = object
    kind: OperandKind
    typ: Type
    reg: x86.Register
    castBits: int             # non-zero only for an okReg operand under an EXPLICIT
                              # sub-width int `(cast …)`: the ALU family then operates
                              # at that width (8/16/32). Never inferred from a
                              # symbol's declared type — existing output is unchanged.
    immVal: int64
    mem: x86.MemoryOperand
    argName: SymId
    label: LabelId
    gvarSym: Symbol           # non-nil when the operand is a global's address; the
                              # ELF backend patches its `lea` against the .bss segment

proc checkPtrStore(dest: Type; srcKind: OperandKind; srcTyp: Type; n: Cursor) =
  if gLenient: return
  ## A `mov` STORES, so it can leave a pointer-typed name holding a non-pointer. The
  ## only integer literals that may be stored into a pointer are `0` and `(nil)`; any
  ## other is a type error. Arch-neutral: both `genMovX64` and the a64 `mov` call it.
  ##
  ## `compatible` cannot make this call, because it also serves COMPARISON, where a
  ## pointer against an arbitrary literal is legitimate — `cmp result, -1` is mmap's
  ## MAP_FAILED test. A compare writes nothing and so cannot corrupt a binding; a store
  ## can. Conflating the two is what left `(mov <ptr-bound name> 32)` assembling
  ## silently: exactly the shape a code generator's stale register binding produces,
  ## which made that whole bug class invisible unless the bad value happened to reach an
  ## instruction carrying its own type rule (`shl`).
  if dest == nil or srcTyp == nil or srcKind != okImm: return
  if srcTyp.kind != TypeKind.IntLitT or srcTyp.litVal == 0: return
  var d = dest
  if d.kind == StackOffT: d = d.offType
  if d.kind in {TypeKind.PtrT, TypeKind.AptrT, TypeKind.ProcT}:
    error("cannot store the non-zero integer " & $srcTyp.litVal &
          " into the pointer-typed destination " & $d & " (only 0 / (nil) may be)", n)

proc intMemAccess(typ: Type): tuple[bits: int; signed: bool] =
  ## A typed memory operand's access width + signedness, so a sub-word field /
  ## element load sign-/zero-extends and a narrow store writes only its low bits.
  ## Pointers / raw `(mem reg)` are full 64-bit accesses.
  ##
  ## A STACK SLOT is its content type behind a `(stackoff …)` wrapper: unwrap it and
  ## size the access by what the slot HOLDS, exactly as the a64 twin `memWidthOpc`
  ## does. A slot always occupies 8 bytes, so this is not about layout — it is what
  ## makes a narrow local's home behave like the variable it is, instead of reading
  ## back the seven bytes above it.
  if typ == nil: return (64, false)
  var t = typ
  if t.kind == StackOffT and t.offType != nil: t = t.offType
  case t.kind
  of IntT: (t.bits, true)
  of UIntT: (t.bits, false)
  of BoolT: (8, false)
  else: (64, false)

proc movTypeOk(destKind: OperandKind; destTyp: Type;
               opKind: OperandKind; opTyp: Type): bool =
  ## THE type rule for `mov`, shared by `genMovX64` and the a64 `MovA64` arm so the
  ## two arches accept exactly the same programs. Both used to carry their own
  ## spelling of it and had drifted: only x86-64 admitted the narrowing `(arg …)`
  ## store below, so the same arkham output was legal on one target and a type error
  ## on the other.
  ##
  ## The rule is kind-aware on purpose. A register operand's declared type never
  ## reaches the encoder — a reg↔reg `mov` emits the full-width form either way, and
  ## only a MEMORY operand sizes its access (`intMemAccess` / `memWidthOpc`). So the
  ## width pairings that are safe depend on where the operands live, not just on what
  ## they are:
  ##
  ## * `sizedMemReg` — exactly one side is memory: a load into a 64-bit register
  ##   sign-/zero-extends a narrower field, and a store writes only the low bits. Any
  ##   width pairing is fine; the sized emit does the work.
  ## * `movCompatible` — the strict core: same width (either signedness), a widening
  ##   integer move, a literal that fits by value, the address-width family, and the
  ##   `StackOffT` unwrap for slots named directly.
  ## * `narrowingArg` — a wider value into a NARROWER call argument is the ABI
  ##   truncation C also performs: the callee reads only the low `param.bits` of the
  ##   argument register, which a plain 64-bit mov already leaves correct.
  ##
  ## Everything else stays an error. In particular a narrowing move into a plain
  ## register or variable (`okReg`) is NOT accepted — that is what catches binding an
  ## `i64` call result to a `u8` var (`result_type_mismatch`), and legitimate typed
  ## narrowing in source always carries an explicit `(conv)`.
  if destTyp == nil or opTyp == nil: return true
  proc isIntLike(t: Type): bool =
    ## A STACK SLOT holding an integer is sized integer memory like any `(dot …)` or
    ## `(at …)`: the emit unwraps the `(stackoff …)` and picks the access width from
    ## the content type, so the pairing is as safe here as it is there.
    var u = t
    if u.kind == StackOffT and u.offType != nil: u = u.offType
    u.kind in {TypeKind.IntT, TypeKind.UIntT, TypeKind.BoolT, TypeKind.IntLitT}
  let sizedMemReg = (destKind == okMem) != (opKind == okMem) and
                    isIntLike(destTyp) and isIntLike(opTyp)
  if sizedMemReg: return true
  if movCompatible(destTyp, opTyp): return true
  let narrowingArg = destKind == okArg and opKind != okMem and
                     destTyp.kind in {TypeKind.IntT, TypeKind.UIntT, TypeKind.BoolT} and
                     opTyp.kind in {TypeKind.IntT, TypeKind.UIntT, TypeKind.IntLitT} and
                     opTyp.bits > intMemAccess(destTyp).bits
  result = narrowingArg

proc inCall(ctx: GenContext): bool {.inline.} =
  ## Returns true if we're inside a prepare block
  ctx.callContext.state != CallContextState.Disabled

template nameOf(ctx: GenContext; s: SymId): string =
  ## Render a `SymId` back to its qualified name string (for the foreign-index
  ## lookup, dedup keys, diagnostics and extern emission — the genuine string sinks).
  poolSym(ctx.pool, s)

template symIdOf(ctx: GenContext; s: string): SymId =
  ## Intern a qualified name into the main pool, yielding its scope key. Cheap for a
  ## name already interned (parsing interned every symbol) — a single hash + probe.
  ctx.pool.syms.getOrIncl(s)

proc markSymbolUsed(ctx: var GenContext; fullName: string) =
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

proc getCanonicalName(ctx: GenContext; fullName: string): string =
  ## Get the canonical name for a symbol (for dedup merging)
  let dedupKey = extractDedupKey(fullName)
  if dedupKey != "" and dedupKey in ctx.dedupTable:
    result = ctx.dedupTable[dedupKey]
  else:
    result = fullName

proc findParam(t: Type; name: SymId): ptr Param =
  ## Find a parameter by its interned id in a ProcT type
  assert t.kind == ProcT
  for i in 0..<t.params.len:
    if t.params[i].name == name:
      return addr t.params[i]
  nil

proc findResult(t: Type; name: SymId): ptr Param =
  ## Find a result by its interned id in a ProcT type
  assert t.kind == ProcT
  for i in 0..<t.results.len:
    if t.results[i].name == name:
      return addr t.results[i]
  nil

proc computeStackArgSize(t: Type): int =
  ## Compute total size needed for stack arguments. Rounded up to 16 bytes so a
  ## caller can `sub sp, sp, #csize` and keep SP 16-byte aligned (required by
  ## AArch64; harmless for x86-64 where the SysV ABI also wants 16-alignment).
  assert t.kind == ProcT
  result = 0
  for param in t.params:
    if param.typ.isOnStack:
      result += slots.alignedSize(param.typ)
  result = (result + 15) and not 15

proc parseType(n: var Cursor; scope: Scope; ctx: var GenContext): Type
proc parsePtrType(kind: TypeKind; n: var Cursor; scope: Scope; ctx: var GenContext): Type
proc parseParams(n: var Cursor; scope: Scope; ctx: var GenContext): seq[Param]
proc parseResult(n: var Cursor; scope: Scope; ctx: var GenContext): seq[Param]
proc rawTagIsMFloatReg(t: TagEnum): bool {.inline.} =
  ## `(s0)`..`(s31)` — the FPv4-SP single-precision file. These spellings are
  ## AArch64's too; `(arch …)` is what decides which machine they name.
  t >= S0TagId and t <= S31TagId

proc rawTagIsMGpr(t: TagEnum): bool {.inline.} =
  ## A Cortex-M GENERAL-purpose register. `rawTagIsMReg` covers the float file
  ## as well, so every site that means "an integer register" has to say so —
  ## otherwise `(s3)` binds a variable to r3.
  rawTagIsMReg(t) and not rawTagIsMFloatReg(t)

proc parseClobbers(n: var Cursor; a64: var set[arm64.Register];
                   m: var set[thumb2.Register]): set[x86.Register]
proc tagToRegisterA64(t: TagEnum; n: Cursor): arm64.Register
proc tagToRegisterM(t: TagEnum; n: Cursor): thumb2.Register
proc parseExtprocSig(n: var Cursor; scope: Scope; ctx: var GenContext): Type
proc parseUnionBody(n: var Cursor; scope: Scope; ctx: var GenContext): Type
proc genStmt(n: var Cursor; ctx: var GenContext)
proc genInstA64(n: var Cursor; ctx: var GenContext)
proc checkIntegerArithmetic(t: Type; op: string; n: Cursor)
proc checkIntegerType(t: Type; op: string; n: Cursor)
proc checkBitwiseType(t: Type; op: string; n: Cursor)
proc checkComparable(t: Type; op: string; n: Cursor)
proc checkExchangeType(t: Type; op: string; n: Cursor)
proc checkCompatibleTypes(t1, t2: Type; op: string; n: Cursor)
proc checkCmpCompatible(t1, t2: Type; n: Cursor)
proc checkBitwiseCompatible(t1, t2: Type; op: string; n: Cursor)
proc checkArithCompatible(t1, t2: Type; op: string; n: Cursor)
proc checkType(want, got: Type; n: Cursor)

proc atTypeStart(n: Cursor): bool =
  ## True if `n` is positioned at the start of a `Type` (a named-type symbol or
  ## a recognized type tag) — i.e. NOT at an Empty/pragmas slot. Used to make
  ## Leng's optional pragmas/base slots tolerant.
  n.kind == Symbol or (n.kind == TagLit and rawTagIsNifasmType(n.tag))

proc parseObjectBody(n: var Cursor; scope: Scope; ctx: var GenContext): Type =
  # Leng `ObjDecl ::= (object [Empty | Type-base] FieldDecl*)` — the `fields`
  # iterator tolerates the optional inheritance/base slot for us.
  var flds: seq[(string, Type, int)] = @[]
  var offset = 0
  var maxAlign = 1  # Track maximum alignment requirement

  # Inheritance: a leading base-type Symbol contributes ITS fields first (at
  # their own base offsets) and its full size as the starting offset for this
  # object's own fields. This mirrors Leng's object layout — typenav.typeOfField
  # searches the base recursively for an inherited field, and nimony's sizeof
  # lays the base out before the own fields, so derived fields begin exactly at
  # `sizeof(Base)` (base tail-padding included). arkham emits the base as the
  # first child of `(object …)`; a `.`/no slot means no inheritance.
  var baseC = n                   # a copy; `n` is walked by `fields(n)` below
  into baseC:
    # `baseC.hasMore` guards an EMPTY object body `(object)` — arkham emits a baseless
    # object with no base slot (the base is only present when there IS one), so a
    # fieldless `ref object` is just `(object)` with zero children; without this guard
    # `baseC.kind` reads past the end. A 0-field object is a valid 0-byte type.
    if baseC.hasMore and baseC.kind == Symbol:
      let baseType = parseType(baseC, scope, ctx)
      if baseType.kind != ObjectT:
        error("object base type must be an object", baseC)
      flds = baseType.fields      # inherited fields keep their base offsets
      offset = baseType.size      # own fields start after the complete base
      maxAlign = baseType.align
    while baseC.hasMore: skip baseC  # drain the field children (read via `n`)

  for fc in fields(n):
    if atTag(fc, UnionTagId):
      # An object VARIANT's union part: a region of `max(branchSize)` bytes whose
      # branches overlap. Place it at the next aligned offset and rebase the union's
      # (branch-local) field offsets onto it, then advance past the whole region.
      var u = fc
      let ut = parseUnionBody(u, scope, ctx)
      offset = alignTo(offset, ut.align)
      for (fn, ft, foff) in ut.fields:
        flds.add (fn, ft, offset + foff)
      if ut.align > maxAlign: maxAlign = ut.align
      offset += ut.size
      continue
    if not atTag(fc, FldTagId): error("Expected field definition or union", fc)
    var f = fc
    # Leng `FieldDecl ::= (fld SymbolDef FieldPragmas Type)` — takeField
    # tolerates the optional field-pragmas slot before the type.
    let fr = takeField(f, atTypeStart)
    var nameC = fr.name
    if nameC.kind != SymbolDef: error("Expected field name", nameC)
    let name = symName(nameC)
    var typC = fr.typ
    let ftype = parseType(typC, scope, ctx)

    # Align field to its natural alignment, then record its offset.
    let fieldAlign = asmAlignOf(ftype)
    offset = alignTo(offset, fieldAlign)
    flds.add (name, ftype, offset)

    # Track maximum alignment for the struct
    if fieldAlign > maxAlign:
      maxAlign = fieldAlign

    # Move past this field
    offset += asmSizeOf(ftype)
  skip n # advance past the whole (object …) node

  # Round up total size to be a multiple of the struct's alignment
  let finalSize = alignTo(offset, maxAlign)
  result = Type(kind: ObjectT, fields: flds, size: finalSize, align: maxAlign)

proc isRegTag(locTag: TagEnum): bool =
  rawTagIsX64Reg(locTag) or rawTagIsA64Reg(locTag)

proc importOrdinal(ctx: var GenContext; libPath: string): int =
  ## The ordinal of `libPath` in the image's import table, importing it if this is
  ## the first mention. One accessor for all three callers so a library named by
  ## the main module and by a foreign one lands in a single entry.
  for lib in ctx.imports:
    if lib.name == libPath: return lib.ordinal
  result = ctx.imports.len + 1
  ctx.imports.add ImportedLib(name: libPath, ordinal: result)

proc extprocLib(ctx: var GenContext; n: var Cursor): int =
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

proc openForeignModule(ctx: var GenContext; modname: string; n: Cursor) =
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

proc allocTlsSlotX64(ctx: var GenContext; sym: Symbol; decl: Cursor) =
  ## x86-64: give a thread-local its displacement inside the unified
  ## `arkham.tls.0` block, and record a literal initializer so `setupTls` can bake
  ## it into the block's image. The block is ordinary `.bss` and nothing runs
  ## before `main` to fill it, so an initializer that is not baked in is simply
  ## LOST — `(tvar :t . (i 64) 7)` then read 0. Three callers allocate an offset
  ## (foreign decl, main-module pre-pass, `generateSymbol`); all three come here so
  ## the initializer cannot be honoured by only some of them.
  sym.offset = ctx.tlsOffset
  ctx.tlsOffset += slots.alignedSize(sym.typ)
  var dn = decl
  let lc = takeLocal(dn)
  if lc.hasVal and lc.val.kind == IntLit:
    ctx.tlsInits.add (off: int64(sym.offset), val: getInt(lc.val),
                      size: asmSizeOf(sym.typ))

proc resolveForeignSym(ctx: var GenContext; modname, fullName: string; scope: Scope; n: Cursor): Symbol =
  ## Resolve ONE foreign declaration by following its qualified name through the
  ## shared `nifmodules` loader: `getDecl` jumps to the indexed byte offset and
  ## parses just that decl (cached, its buffer kept alive in the ForeignModule),
  ## we then define it in `scope` and return it. A decl's body pulls in further
  ## declarations the same lazy way, on demand — so forward and self/mutually-
  ## recursive references resolve naturally regardless of file order (a pointer
  ## pointee stays nominal via `parsePtrType`; only a by-value reference forces a
  ## follow). `declStart` is unused for foreign symbols — generateSymbol re-reads
  ## the cached decl by name.
  let m = ctx.modules[modname]            # ref: stable across table growth
  if not hasDecl(m.foreign, fullName): return nil
  var c = getDecl(m.foreign, fullName, asmTags, ctx.pool)  # cursor at the one decl tree
  let declStartCur = c                    # the un-entered decl (a tvar reads its initializer)
  let declTag = tagToNifasmDecl(c.tag)
  case declTag
  of TypeD:
    inc c                                 # enter: type tag → name
    if c.kind != SymbolDef: return nil
    discard getSymDef(c)                  # advance past the name
    # Define a placeholder BEFORE parsing the body so a self/mutually-recursive
    # by-value reference inside it (e.g. a proctype field whose result names this
    # very type) resolves to this symbol instead of recursing back into here. The
    # placeholder is filled in place, so the captured reference observes the
    # resolved type.
    result = Symbol(name: ctx.symIdOf(fullName), kind: skType, typ: Type(kind: ErrorT),
                    isForeign: true, moduleName: modname)
    ctx.rootScope.define(result)
    var parsed: Type
    if c.kind == TagLit and c.tag == ObjectTagId:
      parsed = parseObjectBody(c, scope, ctx)
    elif c.kind == TagLit and c.tag == UnionTagId:
      parsed = parseUnionBody(c, scope, ctx)
    else:
      parsed = parseType(c, scope, ctx)
    result.typ[] = parsed[]
  of ProcD:
    inc c
    if c.kind != SymbolDef: return nil
    discard getSymDef(c)
    var procTyp = Type(kind: ProcT, params: @[], results: @[], clobbers: {})
    block:
      let sig = takeSig(c)
      if sig.hasParams:
        var p = sig.params; procTyp.params = parseParams(p, scope, ctx)
      if sig.hasResult:
        var r = sig.res; procTyp.results = parseResult(r, scope, ctx)
      if sig.hasClobber:
        var cl = sig.clobber
        procTyp.clobbers = parseClobbers(cl, procTyp.clobbersA64, procTyp.clobbersM)
        procTyp.hasClobberDecl = true
    result = Symbol(name: ctx.symIdOf(fullName), kind: skProc, typ: procTyp, offset: -1,
                    isForeign: true, moduleName: modname)
    ctx.rootScope.define(result)
  of GvarD:
    inc c
    if c.kind != SymbolDef: return nil
    discard getSymDef(c)
    let typ = parseType(c, scope, ctx)
    result = Symbol(name: ctx.symIdOf(fullName), kind: skGvar, typ: typ, isForeign: true,
                    moduleName: modname)
    ctx.rootScope.define(result)
  of TvarD:
    inc c
    if c.kind != SymbolDef: return nil
    discard getSymDef(c)
    let typ = parseType(c, scope, ctx)
    result = Symbol(name: ctx.symIdOf(fullName), kind: skTvar, typ: typ, isForeign: true,
                    moduleName: modname)
    ctx.rootScope.define(result)
    # x86-64 bakes a thread-local's FS displacement at every *reference* site (no
    # relocation), so the offset must be fixed BEFORE the first reference. A
    # reference resolves the symbol through here first, so allocate the FS offset
    # eagerly now — exactly like the main-module tvar pre-pass — and mark it
    # generated so `generateSymbol` does not re-allocate (which would advance
    # `tlsOffset` twice and hand out two offsets for the same tvar). The main-module
    # pre-pass only walks the main buffer, so foreign-module tvars (e.g. the stdlib
    # allocator's thread-local `MemRegion`) would otherwise keep the default offset 0
    # until their lazy `generateSymbol`, baking offset 0 into any earlier reference
    # and the real offset into later ones — a size field then aliases what a pointer
    # field should be. (macOS/A64 relocates tvars through descriptors and allocates
    # lazily in `generateSymbol`, so leave that path untouched.)
    if ctx.arch == Arch.X64 and ctx.nameOf(result.name) notin ctx.generatedSymbols:
      allocTlsSlotX64(ctx, result, declStartCur)
      ctx.generatedSymbols.incl ctx.nameOf(result.name)
  of RodataD:
    # A foreign read-only data blob (e.g. a string literal, or a gvar with a
    # constant-scalar initializer laid out as static data — see arkham genGlobal).
    var probe = c              # the un-entered decl, for the `(reloc …)` scan below
    inc c
    if c.kind != SymbolDef: return nil
    result = Symbol(name: ctx.symIdOf(fullName), kind: skRodata, offset: -1, isForeign: true,
                    moduleName: modname)
    # A blob with symbol-pointer fields must be flagged here too — exactly as pass 1
    # flags a main-module one. Without it the Mach-O path leaves a foreign vtable in
    # read-only __TEXT, where no rebase can reach its pointer fields, so every one of
    # them reads back as 0 (a `=destroy` hook dispatched through it branches to null).
    into probe:
      skip probe               # name
      skip probe               # bytes string literal
      if probe.hasMore:        # one or more trailing (reloc ...) children
        result.dataConst = true
      while probe.hasMore: skip probe   # drain so `into` sees rem == 0
    ctx.rootScope.define(result)
  of ExtprocD:
    # A foreign module's dynamic libc extern (`(extproc :write.c.<mod> "_write")` —
    # arkham emits each used extern's decl in the module that declares the `importc`;
    # a bundle whose MAIN module has no externs of its own still reaches them here).
    # Mirrors the main-module pass-1 ExtprocD case: define the skExtProc symbol with
    # its external name and a fresh GOT slot, and register it for import binding.
    inc c
    if c.kind != SymbolDef: return nil
    discard getSymDef(c)
    if c.kind != StrLit: return nil
    let extName = getStr(c)
    inc c
    let libOrdinal = ctx.extprocLib(c)           # the decl's own dll operand
    let typ = parseExtprocSig(c, scope, ctx)     # the Windows form carries a signature
    let gotSlot = ctx.gotSlotCount
    ctx.gotSlotCount += 1
    result = Symbol(name: ctx.symIdOf(fullName), kind: skExtProc, typ: typ, extName: extName,
                    libName: "", gotSlot: gotSlot, isForeign: true, moduleName: modname)
    ctx.rootScope.define(result)
    ctx.extProcs.add ExtProcInfo(name: fullName, extName: extName, libOrdinal: libOrdinal,
                                 gotSlot: gotSlot, stubOffset: -1)
  of SyprocD:
    # A foreign syscall (arkham emits each used syscall's `(syproc …)` in the module
    # that declares the `importc`; another module that calls it resolves it here).
    # Mirrors `pass1Syproc`: proctype (params/result/clobber) + number in `offset`.
    inc c
    if c.kind != SymbolDef: return nil
    discard getSymDef(c)
    var procTyp = Type(kind: ProcT, params: @[], results: @[], clobbers: {})
    block:
      let sig = takeSig(c)
      if sig.hasParams:
        var p = sig.params; procTyp.params = parseParams(p, scope, ctx)
      if sig.hasResult:
        var r = sig.res; procTyp.results = parseResult(r, scope, ctx)
      if sig.hasClobber:
        var cl = sig.clobber
        procTyp.clobbers = parseClobbers(cl, procTyp.clobbersA64, procTyp.clobbersM)
        procTyp.hasClobberDecl = true
    let sysNr = if c.kind == IntLit: int(getInt(c)) else: 0
    result = Symbol(name: ctx.symIdOf(fullName), kind: skSysProc, typ: procTyp, offset: sysNr,
                    isForeign: true, moduleName: modname)
    ctx.rootScope.define(result)
  else:
    return nil

proc lookupWithAutoImport(ctx: var GenContext; scope: Scope; name: string; n: Cursor): Symbol =
  ## Lookup a symbol, lazily opening + following names into foreign modules.
  ## Also marks the symbol as used for dependency tracking.
  ##
  ## Important: Symbols with module suffixes (e.g., `foo.0.mymodule`) are distinct
  ## from local symbols (e.g., `foo.0`). When a module suffix is present, we only
  ## look in the foreign module, not in the local scope.
  let modname = extractModule(name)
  if modname != "" and modname != ctx.thisModule:
    # Foreign symbol: open the module's index, then resolve this one decl lazily
    # if it isn't already in scope. (A `…0.<thisModule>` suffix names *this*
    # module's own symbol — arkham emits self-module globals fully qualified — so
    # it must NOT be treated as foreign, which would shadow the local definition.)
    openForeignModule(ctx, modname, n)
    result = scope.lookup(ctx.symIdOf(name))
    if result == nil:
      result = resolveForeignSym(ctx, modname, name, scope, n)
  else:
    # This is a local symbol - look up in current scope
    result = scope.lookup(ctx.symIdOf(name))

  # Mark symbol as used for dependency tracking
  if result != nil:
    # Redirect a deduplicated duplicate to its CANONICAL symbol so every reference
    # shares ONE symbol — hence ONE label. A weak/COMDAT proc or data blob (e.g. an
    # enum `$`) is emitted in several modules with the same dedup key but only its
    # canonical copy's body is generated (processReachableSymbols); a reference left
    # pointing at a non-canonical duplicate's own (never-defined) label id would fail
    # linking with "Label not found". First sighting of a key becomes canonical; later
    # duplicates resolve back to it (its symbol is already in scope from that sighting).
    let resultName = ctx.nameOf(result.name)
    let dedupKey = extractDedupKey(resultName)
    if dedupKey != "" and dedupKey in ctx.dedupTable and
       ctx.dedupTable[dedupKey] != resultName:
      let canon = scope.lookup(ctx.symIdOf(ctx.dedupTable[dedupKey]))
      if canon != nil: result = canon
    # `markSymbolUsed` owns dedupTable registration + pending-queue insertion for the
    # first-seen (canonical) name; we only READ the table above to redirect duplicates.
    markSymbolUsed(ctx, resultName)

proc parsePtrType(kind: TypeKind; n: var Cursor; scope: Scope; ctx: var GenContext): Type =
  ## Parse the pointee of a `(ptr X)` / `(aptr X)`. A pointer is 8 bytes whatever
  ## it points at, so a bare-symbol pointee carries its qualified NAME in
  ## `baseName` — this is its nominal identity (used for strict, name-based
  ## pointer compatibility, see `compatible`) and, when the type is not yet
  ## defined, the handle for resolving it lazily on first structural access (see
  ## `resolvedBase`). An already-defined symbol also resolves `base` eagerly; a
  ## genuine forward reference (pointee declared later in the still-loading
  ## module, e.g. `(ptr Rtti)`) leaves `base` nil until forced. A structural
  ## pointee (`(ptr (i 32))`) has no name and is resolved eagerly.
  var base: Type = nil
  var baseName = ""
  if n.kind == Symbol:
    baseName = getSym(n)
    let sym = scope.lookup(getSymId(n))
    inc n
    if sym != nil and sym.kind == skType:
      base = sym.typ          # resolved eagerly, but keep baseName (nominal id)
  else:
    base = parseType(n, scope, ctx)
  # Construct with a literal discriminator (Nim can't prove a runtime one safe).
  if kind == AptrT:
    result = Type(kind: AptrT, base: base, baseName: baseName)
  else:
    result = Type(kind: PtrT, base: base, baseName: baseName)

proc resolvedBase(t: Type; ctx: var GenContext; n: Cursor): Type =
  ## Return a pointer/aptr's pointee, resolving & memoizing a lazily-recorded
  ## forward reference (see `parsePtrType`) on first use. By the time any field
  ## or element access runs, the pointee's declaration has been parsed, so the
  ## lookup — which also auto-imports the owning module if needed — succeeds.
  if t.base == nil and t.baseName.len > 0:
    let sym = lookupWithAutoImport(ctx, ctx.scope, t.baseName, n)
    if sym == nil or sym.kind != skType:
      error("Unknown type: " & t.baseName, n)
    t.base = sym.typ
  result = t.base

proc parseType(n: var Cursor; scope: Scope; ctx: var GenContext): Type =
  if n.kind == Symbol:
    let name = getSym(n)
    let sym = lookupWithAutoImport(ctx, scope, name, n)
    if sym == nil or sym.kind != skType:
      error("Unknown type: " & name, n)
    result = sym.typ
    inc n
  elif n.kind == TagLit:
    let t = n.tag
    # Inline aggregate types (e.g. an array of anonymous objects, or a field
    # whose type is spelled out in place) — parseObjectBody/parseUnionBody each
    # consume the whole `(object …)`/`(union …)` tree, so return directly.
    if t == ObjectTagId:
      return parseObjectBody(n, scope, ctx)
    elif t == UnionTagId:
      return parseUnionBody(n, scope, ctx)
    var nodeEnd = n
    skip nodeEnd          # a cursor positioned just past this whole type node
    inc n
    case t
    of BoolTagId:
      result = Type(kind: BoolT)
    of NilTagId:
      result = Type(kind: NilT)
    of ITagId:
      result = Type(kind: IntT, bits: normScalarBits(getInt(n)))
      inc n
    of UTagId:
      result = Type(kind: UIntT, bits: normScalarBits(getInt(n)))
      inc n
    of FTagId:
      result = Type(kind: FloatT, bits: normScalarBits(getInt(n)))
      inc n
    of PtrTagId:
      result = parsePtrType(PtrT, n, scope, ctx)
    of AptrTagId:
      result = parsePtrType(AptrT, n, scope, ctx)
    of ArrayTagId:
      let elem = parseType(n, scope, ctx)
      let len = getInt(n)
      inc n
      result = Type(kind: ArrayT, elem: elem, len: len)
    of ProcTagId:
      # (proc (params ...) (result ...) (clobber ...))
      var procTyp = Type(kind: ProcT, params: @[], results: @[], clobbers: {})
      let sig = takeSig(n)
      if sig.hasParams:
        var p = sig.params; procTyp.params = parseParams(p, scope, ctx)
      if sig.hasResult:
        var r = sig.res; procTyp.results = parseResult(r, scope, ctx)
      if sig.hasClobber:
        var cl = sig.clobber
        procTyp.clobbers = parseClobbers(cl, procTyp.clobbersA64, procTyp.clobbersM)
        procTyp.hasClobberDecl = true
      result = procTyp
    of CTagId:
      # Leng character type `(c N)` — an N-bit UNSIGNED integer for the machine.
      # Unsigned is not cosmetic: `intMemAccess`/`memWidthOpc` derive the extension
      # of a sub-word load from the kind, so an `IntT` char made `(mem p)` on a
      # `(ptr (c 8))` emit `movsbq` and every byte ≥ 0x80 arrived as a negative
      # number (`c shr 3` in a `set[char]` test then indexed far out of bounds).
      # The C backend agrees: `typedef unsigned char NC8`, and arkham's own
      # `isSignedType` already answers false for `CT`.
      result = Type(kind: UIntT, bits: normScalarBits(getInt(n)))
      inc n
    of VoidTagId:
      result = Type(kind: VoidT)
    of VarargsTagId:
      # `(varargs)` — a zero-size variadic marker; modeled as void.
      result = Type(kind: VoidT)
    of FlexarrayTagId:
      # `(flexarray T)` — flexible array member: a zero-length array of T.
      let elem = parseType(n, scope, ctx)
      result = Type(kind: ArrayT, elem: elem, len: 0)
    of EnumTagId:
      # `(enum BaseType EnumFieldDecl*)` — collapses to its base integer type
      # for codegen; the `efld` children are consumed by the trailing skip.
      result = parseType(n, scope, ctx)
    of ProctypeTagId:
      # `(proctype (params …) (result …)? (clobber …)?)` — a function pointer
      # (8 bytes; see `asmSizeOf`). arkham emits the full ABI signature (not an
      # opaque pointer) so an indirect `(prepare <fnptr> … (call))` resolves its
      # args/result against this, exactly like a direct call to a proc.
      var ptParams: seq[Param] = @[]
      var ptResults: seq[Param] = @[]
      var ptClobbers: set[x86.Register] = {}
      var ptClobbersA64: set[arm64.Register] = {}
      var ptClobbersM: set[thumb2.Register] = {}
      var ptHasClobberDecl = false
      let sig = takeSig(n)
      if sig.hasParams:
        var p = sig.params; ptParams = parseParams(p, scope, ctx)
      if sig.hasResult:
        var r = sig.res; ptResults = parseResult(r, scope, ctx)
      if sig.hasClobber:
        var cl = sig.clobber; ptClobbers = parseClobbers(cl, ptClobbersA64, ptClobbersM)
        ptHasClobberDecl = true
      result = Type(kind: ProcT, params: ptParams, results: ptResults, clobbers: ptClobbers,
                    clobbersA64: ptClobbersA64, hasClobberDecl: ptHasClobberDecl)
    else:
      error("Unknown type tag: " & $t, n)
    # Jump to the precomputed node end: this consumes any Leng type qualifiers we
    # don't model (IntQualifier atomic/ro, PtrQualifier atomic/ro/restrict, the
    # trailing (cppref) marker) and lands exactly past the whole type node —
    # rem-independent, unlike a `while hasMore` walk over a manually-entered node.
    n = nodeEnd
  else:
    error("Expected type", n)


proc parseUnionBody(n: var Cursor; scope: Scope; ctx: var GenContext): Type =
  ## A union's members OVERLAP (max size, shared base). Leng object VARIANTS spell each
  ## branch as a nested `(object …)` whose fields are SEQUENTIAL — so a branch's fields
  ## keep their intra-branch offsets and only branches overlap. A bare `(fld …)` member
  ## (a flat union) sits at offset 0. Offsets are relative to the union's base; the
  ## enclosing `parseObjectBody` rebases them.
  var flds: seq[(string, Type, int)] = @[]
  var maxSize = 0
  var maxAlign = 1  # Track maximum alignment requirement
  var c = n
  into c:
    while c.hasMore:
      if atTag(c, ObjectTagId):                # a variant branch: sequential fields
        var b = c
        let bt = parseObjectBody(b, scope, ctx)  # 0-based branch field offsets + size
        for f in bt.fields: flds.add f
        if bt.size > maxSize: maxSize = bt.size
        if bt.align > maxAlign: maxAlign = bt.align
        skip c
      elif atTag(c, FldTagId):                 # a flat union member at offset 0
        var f = c
        let fr = takeField(f, atTypeStart)     # tolerates Leng's FieldPragmas slot
        if fr.name.kind != SymbolDef: error("Expected field name", fr.name)
        var typC = fr.typ
        let ftype = parseType(typC, scope, ctx)
        flds.add (symName(fr.name), ftype, 0)
        if asmSizeOf(ftype) > maxSize: maxSize = asmSizeOf(ftype)
        if asmAlignOf(ftype) > maxAlign: maxAlign = asmAlignOf(ftype)
        skip c
      else:
        error("union member must be an object branch or a field", c)
  skip n # advance past the whole (union …) node

  # Round up size to be a multiple of the union's alignment
  let finalSize = alignTo(maxSize, maxAlign)
  result = Type(kind: UnionT, fields: flds, size: finalSize, align: maxAlign)

proc parseParams(n: var Cursor; scope: Scope; ctx: var GenContext): seq[Param] =
  # (params (param :name (reg) Type) ...)
  for pc in params(n):
    if declTag(pc) != ParamD: error("Expected param declaration", pc)
    var p = pc
    let pr = takeParam(p)
    var nameC = pr.name
    if nameC.kind != SymbolDef: error("Expected param name", nameC)
    let name = getSymId(nameC)

    # (reg) / (regs (r0) (r1) …) / (s) location
    var loc = pr.location
    var reg = InvalidTagId
    var regs: seq[TagEnum] = @[]
    var onStack = false
    var viaRegs = false
    if loc.kind == TagLit:
      let locTag = rawTag(loc)
      if rawTagIsX64Reg(locTag) or rawTagIsA64Reg(locTag):
        reg = locTag
        regs = @[locTag]
      elif locTag == STagId:
        onStack = true
      elif locTag == RegsTagId:
        # An aggregate param (≤16B by-value spread over several registers, or a >16B
        # by-ref pointer in one) consumed RAW by the code generator — ABI-only, not bound.
        viaRegs = true
        var rc = loc
        into rc:
          while rc.hasMore:
            if rc.kind != TagLit or
               not (rawTagIsX64Reg(rawTag(rc)) or rawTagIsA64Reg(rawTag(rc))):
              error("expected register in (regs …)", rc)
            regs.add rawTag(rc)
            skip rc
        if regs.len == 0: error("empty (regs …)", loc)
        reg = regs[0]
      else:
        error("Expected location", loc)
    else:
      error("Expected location", loc)

    var typC = pr.typ
    var typ = parseType(typC, scope, ctx)
    if onStack:
      typ = Type(kind: StackOffT, offType: typ)
    result.add Param(name: name, typ: typ, reg: reg, regs: regs, viaRegs: viaRegs)
  skip n # advance past the whole (params …) node

proc parseResult(n: var Cursor; scope: Scope; ctx: var GenContext): seq[Param] =
  # (result (ret :name (reg) Type) ...)
  if n.kind == TagLit and tagToNifasmDecl(n.tag) == ResultD:
    loopInto n:
      # An entry is either wrapped `(ret :name (reg) Type)` or the three slots
      # `:name (reg) Type` inline. Either way we consume them linearly, so the
      # loop's bound stays correct; the (elided) wrapper close needs no skip.
      if n.kind == TagLit:
        enterNode n                 # enter the (ret …) wrapper
      if n.kind != SymbolDef: error("Expected result definition", n)
      let name = getSymId(n)
      skip n
      var reg = InvalidTagId
      if n.kind == TagLit:
        let locTag = n.tag
        if isRegTag(locTag):
          reg = locTag
          skip n                    # the whole (reg) location node
        else:
          error "result must be a register", n
      else:
        error("Expected location", n)
      let typ = parseType(n, scope, ctx)
      result.add Param(name: name, typ: typ, reg: reg)

proc parseClobbers(n: var Cursor; a64: var set[arm64.Register];
                   m: var set[thumb2.Register]): set[x86.Register] =
  # (clobber (rax) (rbx) ...) — or its AArch64 twin (clobber (x0) (x1) ...), or
  # Cortex-M's (clobber (r0) (r1) ...).
  #
  # A Cortex-M register tag is ALSO a valid x86-64 one (`(r0)` is an alias for
  # rax there), so such a tag is recorded in BOTH sets rather than routed by a
  # target this proc cannot see. Each arch then reads its own set, and since a
  # declaration only ever names one arch's registers the extra membership is
  # never consulted.
  if declTag(n) == ClobberD:
    loopInto n:
      if n.kind == TagLit and rawTagIsX64Reg(rawTag(n)):
        if rawTagIsMGpr(rawTag(n)): m.incl tagToRegisterM(n.tag, n)
        result.incl parseRegister(n)
      elif n.kind == TagLit and rawTagIsMGpr(rawTag(n)):
        m.incl tagToRegisterM(n.tag, n)
        skip n
      elif n.kind == TagLit and rawTagIsA64Reg(rawTag(n)):
        a64.incl tagToRegisterA64(n.tag, n)
        skip n
      else:
        error("Expected register in clobber list", n)

proc pass1Proc(n: var Cursor; scope: Scope; ctx: var GenContext; moduleName: string; declStart: int) =
  # (proc :Name (params ...) (result ...) (clobber ...) (body ...))
  inc n
  if n.kind != SymbolDef: error("Expected proc name", n)
  let name = symName(n)  # Full qualified name
  inc n

  var procTyp = Type(kind: ProcT, params: @[], results: @[], clobbers: {})

  let sig = takeSig(n)
  if sig.hasParams:
    var p = sig.params; procTyp.params = parseParams(p, scope, ctx)
  if sig.hasResult:
    var r = sig.res; procTyp.results = parseResult(r, scope, ctx)
  if sig.hasClobber:
    var cl = sig.clobber
    procTyp.clobbers = parseClobbers(cl, procTyp.clobbersA64, procTyp.clobbersM)
    procTyp.hasClobberDecl = true

  let sym = Symbol(name: ctx.symIdOf(name), kind: skProc, typ: procTyp, offset: -1,
                   moduleName: moduleName, declStart: declStart)
  scope.define(sym)

proc parseExtprocSig(n: var Cursor; scope: Scope; ctx: var GenContext): Type =
  ## The OPTIONAL `(params …)(result …)(clobber …)` tail of an `(extproc :name "ext" …)`,
  ## advancing `n` past it. `nil` when the decl carries none.
  ##
  ## A signature turns the extern into an ordinary declarative call target: the call site
  ## binds `(arg pN)`/`(res ret.0)` and is type-checked against it, and the frame pre-scan
  ## can size the call's outgoing stack-argument area — neither of which a bare extern
  ## permits, because there is nothing to check against and no way to know how many
  ## arguments spill. The Windows backend declares one for every import (`emitWinExtproc`);
  ## the Darwin one declares none and marshals into raw ABI registers at the call site,
  ## which is why both forms have to keep working.
  let sig = takeSig(n)
  if not (sig.hasParams or sig.hasResult or sig.hasClobber): return nil
  result = Type(kind: ProcT, params: @[], results: @[], clobbers: {})
  if sig.hasParams:
    var p = sig.params; result.params = parseParams(p, scope, ctx)
  if sig.hasResult:
    var r = sig.res; result.results = parseResult(r, scope, ctx)
  if sig.hasClobber:
    var cl = sig.clobber
    result.clobbers = parseClobbers(cl, result.clobbersA64, result.clobbersM)
    result.hasClobberDecl = true

proc pass1Syproc(n: var Cursor; scope: Scope; ctx: var GenContext; moduleName: string; declStart: int) =
  # (syproc :Name (params ...) (result ...) (clobber ...) NR) — a Linux syscall with a
  # full proctype: params bound to the syscall ABI registers (so an `(arg pN)` binding
  # in a `(prepare …)` lands in the right register, e.g. x86-64 arg4 → r10), a result in
  # the kernel's return register, and the registers the syscall instruction clobbers
  # (x86-64: rcx, r11). It has no code/address; the number is kept in `offset` and the
  # `(syscall)`/`(svc)` marker reads it. See genSyscallMarker*.
  inc n
  if n.kind != SymbolDef: error("Expected syproc name", n)
  let name = symName(n)
  inc n

  var procTyp = Type(kind: ProcT, params: @[], results: @[], clobbers: {})
  let sig = takeSig(n)
  if sig.hasParams:
    var p = sig.params; procTyp.params = parseParams(p, scope, ctx)
  if sig.hasResult:
    var r = sig.res; procTyp.results = parseResult(r, scope, ctx)
  if sig.hasClobber:
    var cl = sig.clobber
    procTyp.clobbers = parseClobbers(cl, procTyp.clobbersA64, procTyp.clobbersM)
    procTyp.hasClobberDecl = true

  if n.kind != IntLit: error("Expected syscall number in syproc", n)
  let sysNr = int(getInt(n))

  let sym = Symbol(name: ctx.symIdOf(name), kind: skSysProc, typ: procTyp, offset: sysNr,
                   moduleName: moduleName, declStart: declStart)
  scope.define(sym)

proc handleArch(n: var Cursor; ctx: var GenContext) =
  ## Also fixes the target WORD SIZE for the whole assembly. asm-NIF always states
  ## `(arch …)` before any declaration, so every type is built under the right
  ## width — and arkham's `slots.setTargetWord` must have picked the same one, or
  ## a `(i -1)` field is sized differently on the two sides of the pipe.
  inc n
  if n.kind != Ident: error("Expected architecture symbol", n)
  let arch = n.strVal
  if arch == "x64":
    ctx.arch = Arch.X64
  elif arch == "linux_arm64":
    ctx.arch = Arch.LinuxA64
  elif arch == "arm64":
    ctx.arch = Arch.A64
  elif arch == "win_x64":
    ctx.arch = Arch.WinX64
  elif arch == "win_arm64":
    ctx.arch = Arch.WinA64
  elif arch == "cortex_m":
    ctx.arch = Arch.CortexM
  else:
    error("Unknown architecture: " & arch, n)
  setAsmWordSize(case ctx.arch
                 of Arch.X64, Arch.LinuxA64, Arch.A64, Arch.WinX64, Arch.WinA64: 8
                 of Arch.CortexM: 4)
  inc n

proc pass1(n: var Cursor; scope: Scope; ctx: var GenContext; moduleName: string; buf: var TokenBuf) =
  var n = n
  if n.kind == TagLit and n.tag == StmtsTagId:
    loopInto n:
      if n.kind == TagLit:
        let start = n
        let declStart = cursorToPosition(buf, start)
        let declTag = tagToNifasmDecl(n.tag)
        case declTag
        of TypeD:
          inc n
          if n.kind != SymbolDef: error("Expected type name", n)
          let name = symName(n)  # Full qualified name
          inc n
          if n.kind == TagLit and n.tag == ObjectTagId:
            let typ = parseObjectBody(n, scope, ctx)
            scope.define(Symbol(name: ctx.symIdOf(name), kind: skType, typ: typ,
                                moduleName: moduleName, declStart: declStart))
          elif n.kind == TagLit and n.tag == UnionTagId:
            let typ = parseUnionBody(n, scope, ctx)
            scope.define(Symbol(name: ctx.symIdOf(name), kind: skType, typ: typ,
                                moduleName: moduleName, declStart: declStart))
          else:
            let typ = parseType(n, scope, ctx)
            scope.define(Symbol(name: ctx.symIdOf(name), kind: skType, typ: typ,
                                moduleName: moduleName, declStart: declStart))
        of ProcD:
          # (proc :Name (params ...) (result ...) (clobber ...) (body ...))
          pass1Proc(n, scope, ctx, moduleName, declStart)

          n = start
          skip n
        of RodataD:
          inc n
          if n.kind != SymbolDef: error("Expected rodata name", n)
          let name = symName(n)  # Full qualified name
          var sym = Symbol(name: ctx.symIdOf(name), kind: skRodata,
                          moduleName: moduleName, declStart: declStart)
          sym.offset = -1  # Mark as forward reference until defined
          # A `(rodata :name "bytes" (reloc off sym)*)` whose blob carries
          # symbol-pointer fields cannot live in read-only __TEXT on a PIE image:
          # the absolute target vaddr baked in would be stale under the ASLR slide.
          # Flag it so the Mach-O backend places it in writable __DATA and emits a
          # dyld rebase for each pointer field (see writeMachO). Arch-independent
          # flag; only the macOS path acts on it.
          block:
            var probe = start
            into probe:        # bound the cursor to this rodata's children
              skip probe       # name
              skip probe       # bytes string literal
              if probe.hasMore:  # one or more trailing (reloc ...) children
                sym.dataConst = true
              while probe.hasMore: skip probe   # drain so `into` sees rem == 0
          scope.define(sym)
          n = start
          skip n
        of GvarD:
          inc n
          if n.kind != SymbolDef: error("Expected gvar name", n)
          let name = symName(n)  # Full qualified name
          inc n # skip name
          let typ = parseType(n, scope, ctx)
          scope.define(Symbol(name: ctx.symIdOf(name), kind: skGvar, typ: typ,
                              moduleName: moduleName, declStart: declStart))
          n = start
          skip n
        of TvarD:
          inc n
          if n.kind != SymbolDef: error("Expected tvar name", n)
          let name = symName(n)  # Full qualified name
          inc n # skip name
          let typ = parseType(n, scope, ctx)
          scope.define(Symbol(name: ctx.symIdOf(name), kind: skTvar, typ: typ,
                              moduleName: moduleName, declStart: declStart))
          n = start
          skip n
        of ArchD:
          handleArch(n, ctx)
        of ImpD:
          # (imp "libpath")
          inc n
          if n.kind != StrLit: error("Expected library path string", n)
          let libPath = getStr(n)
          inc n
          # Load this library; `(imp …)` no longer decides what BINDS to it — each
          # `(extproc …)` names its own, so an import that only needs loading (the
          # Darwin TLV bootstrap, with no externs at all) is expressible too.
          discard ctx.importOrdinal(libPath)
        of ExtprocD:
          # (extproc :name "external_name" "dll"? (params …)? (result …)? (clobber …)?)
          inc n
          if n.kind != SymbolDef: error("Expected extproc name", n)
          let name = symName(n)
          inc n
          if n.kind != StrLit: error("Expected external symbol name string", n)
          let extName = getStr(n)
          inc n
          let libOrdinal = ctx.extprocLib(n)     # the optional dll operand
          let typ = parseExtprocSig(n, scope, ctx)
          # Allocate GOT slot
          let gotSlot = ctx.gotSlotCount
          ctx.gotSlotCount += 1
          # Create symbol
          let sym = Symbol(name: ctx.symIdOf(name), kind: skExtProc, typ: typ, extName: extName, libName: "", gotSlot: gotSlot)
          scope.define(sym)
          # Track for code generation
          ctx.extProcs.add ExtProcInfo(name: name, extName: extName, libOrdinal: libOrdinal, gotSlot: gotSlot, stubOffset: -1)
        of SyprocD:
          # (syproc :name (params ...) (result ...) (clobber ...) NR) — defines a
          # syscall's proctype + number; emits no code (see genSyscallMarker*).
          pass1Syproc(n, scope, ctx, moduleName, declStart)
          n = start
          skip n
        else:
          skip n
      else:
        skip n

proc genInstX64(n: var Cursor; ctx: var GenContext)

proc tagToRegisterA64(t: TagEnum; n: Cursor): arm64.Register =
  ## Convert a TagEnum to an ARM64 Register (for register binding tracking)
  ## Note: X16/X17 are reserved for assembler scratch use but allowed in direct
  ## instructions (e.g., Darwin syscalls use X16 for syscall number).
  let regTag = tagToA64Reg(t)
  result =
    case regTag
    of X0R: arm64.X0
    of X1R: arm64.X1
    of X2R: arm64.X2
    of X3R: arm64.X3
    of X4R: arm64.X4
    of X5R: arm64.X5
    of X6R: arm64.X6
    of X7R: arm64.X7
    of X8R: arm64.X8
    of X9R: arm64.X9
    of X10R: arm64.X10
    of X11R: arm64.X11
    of X12R: arm64.X12
    of X13R: arm64.X13
    of X14R: arm64.X14
    of X15R: arm64.X15
    of X16R: arm64.X16
    of X17R: arm64.X17
    of X18R: arm64.X18
    of X19R: arm64.X19
    of X20R: arm64.X20
    of X21R: arm64.X21
    of X22R: arm64.X22
    of X23R: arm64.X23
    of X24R: arm64.X24
    of X25R: arm64.X25
    of X26R: arm64.X26
    of X27R: arm64.X27
    of X28R: arm64.X28
    of X29R: arm64.X29
    of X30R: arm64.X30
    of SpR: arm64.SP
    of LrR: arm64.LR
    of FpR: arm64.FP
    of XzrR: arm64.Register(31)
    else:
      error("Expected ARM64 register, got: " & $t, n)
      arm64.X0

proc parseRegisterA64(n: var Cursor): arm64.Register =
  result = tagToRegisterA64(n.tag, n)
  inc n

proc isA64DoubleRegTag(t: TagEnum): bool {.inline.} =
  ord(t) >= ord(D0TagId) and ord(t) <= ord(D31TagId)

proc isA64SingleRegTag(t: TagEnum): bool {.inline.} =
  ord(t) >= ord(S0TagId) and ord(t) <= ord(S31TagId)

proc isA64FpRegTag(t: TagEnum): bool {.inline.} =
  ## True for any scalar fp register tag `(d0)`..`(d31)` / `(s0)`..`(s31)`.
  isA64DoubleRegTag(t) or isA64SingleRegTag(t)

proc isA64FpRegOperand(n: Cursor): bool {.inline.} =
  n.kind == TagLit and isA64FpRegTag(n.tag)

proc isA64SingleOperand(n: Cursor): bool {.inline.} =
  ## Whether the fp register operand `n` is single-precision `(sN)`.
  n.kind == TagLit and isA64SingleRegTag(n.tag)

proc parseFloatRegisterA64(n: var Cursor): arm64.FloatRegister =
  if not isA64FpRegOperand(n): error("Expected fp register (dN/sN)", n)
  let base = if isA64SingleRegTag(n.tag): ord(S0TagId) else: ord(D0TagId)
  result = arm64.FloatRegister(ord(n.tag) - base)
  inc n

proc tagToFloatRegA64(t: TagEnum): arm64.FloatRegister {.inline.} =
  let base = if isA64SingleRegTag(t): ord(S0TagId) else: ord(D0TagId)
  result = arm64.FloatRegister(ord(t) - base)

proc fpSymReg(ctx: GenContext; n: Cursor): Symbol =
  ## If `n` is a `Symbol` naming a float local bound to a v-register, return its
  ## symbol; else nil. Float locals are never foreign, so a plain scope lookup suffices.
  if n.kind == Symbol:
    let sym = ctx.scope.lookup(getSymId(n))
    if sym != nil and sym.reg != InvalidTagId and isA64FpRegTag(sym.reg):
      return sym
  return nil

proc isA64FpOperand(n: Cursor; ctx: GenContext): bool =
  ## True if `n` denotes an fp register operand — a raw `(dN)`/`(sN)` tag or a `Symbol`
  ## naming a float local bound to a v-register. The float handlers dispatch on this
  ## (reg-vs-mem / fmov direction) so a bound float local emitted as its name is
  ## recognized as a register operand.
  isA64FpRegOperand(n) or fpSymReg(ctx, n) != nil

proc isA64FpSingle(n: Cursor; ctx: GenContext): bool =
  ## Single-precision (`s` view)? For a raw tag, the `(sN)` form; for a bound float
  ## symbol, the recorded type is `(f 32)`. nifasm reads the operand's precision here
  ## to choose single- vs double-precision encodings — so a *named* float operand must
  ## recover it from the binding rather than the (absent) tag.
  if isA64FpRegOperand(n): return isA64SingleRegTag(n.tag)
  let sym = fpSymReg(ctx, n)
  result = sym != nil and sym.typ.kind == FloatT and sym.typ.bits == 32

proc parseFloatOperandA64(n: var Cursor; ctx: var GenContext): arm64.FloatRegister =
  ## Binding-aware fp register *operand*: a raw `(dN)`/`(sN)` tag is accepted only if
  ## the register is not bound (a bound register must be named so the binding checker
  ## sees the use); a `Symbol` is resolved to the v-register its float local is bound
  ## to. The SIMD twin of `parseGprA64` — turns a raw use of a still-live bound float
  ## register into a build error instead of a silent clobber.
  if isA64FpRegOperand(n):
    result = tagToFloatRegA64(n.tag)
    if result in ctx.a64FRegBindings:
      error("Register " & $result & " is bound to variable '" &
            ctx.a64FRegBindings[result] & "', use the variable name instead", n)
    inc n
  elif n.kind == Symbol:
    let sym = lookupWithAutoImport(ctx, ctx.scope, getSym(n), n)
    if sym == nil: error("Unknown symbol: " & getSym(n), n)
    if sym.reg == InvalidTagId or not isA64FpRegTag(sym.reg):
      error("Expected float register variable, got: " & getSym(n), n)
    result = tagToFloatRegA64(sym.reg)
    inc n
  else:
    error("Expected fp register (dN/sN) or float variable", n)


type
  OperandA64 = object
    kind: OperandKind
    reg: arm64.Register
    typ: Type
    immVal: int64
    mem: arm64.MemoryOperand
    argName: SymId       # set for okArg (call argument / result binding by name)
    label: LabelId
    gvarSym: Symbol       # non-nil if this operand is a global (.bss) address;
                          # its `.size` (the .bss byte offset) is read after all
                          # symbols are processed, so forward refs resolve right
    tlvSym: Symbol        # non-nil if this operand is a thread-local var address
                          # (arm64/macOS): `adr` lowers it to the TLV descriptor
                          # call sequence, leaving the variable's address in x0

proc parseOperandA64(n: var Cursor; ctx: var GenContext): OperandA64 =
  if n.kind == TagLit:
    let t = n.tag
    if rawTagIsA64Reg(t):
      result.reg = parseRegisterA64(n)
      result.typ = Type(kind: RegisterT, regBits: 64) # Pure register - accepts any type
      # A raw use of a register bound to a live variable is a code-generator bug (a
      # silent clobber of the value it holds): spell the variable by name instead.
      if result.reg in ctx.a64RegBindings:
        error("Register " & $result.reg & " is bound to variable '" &
              ctx.a64RegBindings[result.reg] & "', use the variable name instead", n)
    elif t == NilTagId:
      # `(nil)` as a value: the null pointer — a 0 immediate typed `nil` (compatible
      # with any pointer, never a sized integer). See `compatible`'s NilT arm.
      result.kind = okImm
      result.immVal = 0
      result.typ = Type(kind: TypeKind.NilT)
      inc n
    elif t == DotTagId:
      # (dot <base> <fieldname>) - similar to x64
      inc n
      var baseOp = parseOperandA64(n, ctx)
      if n.kind != Symbol:
        error("Expected field name in dot expression", n)
      let fieldName = getSym(n)
      inc n
      var objType: Type
      var baseReg: arm64.Register
      var baseOffset: int32 = 0
      var baseIndex: arm64.Register
      var baseShift = 0
      var baseHasIndex = false
      if baseOp.typ.kind == TypeKind.PtrT:
        objType = resolvedBase(baseOp.typ, ctx, n)
        if objType.kind notin {TypeKind.ObjectT, TypeKind.UnionT}:
          error("Cannot access field of non-object/union type " & $objType, n)
        if baseOp.kind == okMem:
          # The base is itself a memory lvalue — a NESTED access whose result type the
          # `(dot …)`/`(at …)` rule tagged `PtrT(fieldType)` (an embedded sub-object/
          # element sits AT base+offset, not behind a loaded pointer). Fold the field
          # offset onto the inner base+offset (+index) instead of treating the inner
          # base register as the pointer — otherwise `(dot (dot o inner) a)` and
          # `(dot (at arr i) f)` lose the inner displacement. Mirrors the x64 parser.
          baseReg = baseOp.mem.base
          baseOffset = baseOp.mem.offset
          baseIndex = baseOp.mem.index
          baseShift = baseOp.mem.shift
          baseHasIndex = baseOp.mem.hasIndex
        else:
          baseReg = baseOp.reg
      elif baseOp.kind == okMem and baseOp.typ.kind in {TypeKind.ObjectT, TypeKind.UnionT}:
        objType = baseOp.typ
        baseReg = baseOp.mem.base
        baseOffset = baseOp.mem.offset
      elif baseOp.kind == okMem and baseOp.typ.kind == TypeKind.StackOffT and
           baseOp.typ.offType.kind in {TypeKind.ObjectT, TypeKind.UnionT}:
        # a stack-resident object/union: unwrap the StackOffT to its object type
        objType = baseOp.typ.offType
        baseReg = baseOp.mem.base
        baseOffset = baseOp.mem.offset
      else:
        error("dot requires pointer to object/union or stack object/union, got " & $baseOp.typ, n)
      var fieldOffset = 0
      var fieldType: Type = nil
      # Offsets are precomputed in parseObjectBody/parseUnionBody (inherited
      # fields carry their base offsets), so a plain name lookup suffices.
      for (fname, ftype, foff) in objType.fields:
        if fname == fieldName:
          fieldType = ftype
          fieldOffset = foff
          break
      if fieldType == nil:
        error("Field '" & fieldName & "' not found in " & $objType.kind, n)
      result.kind = okMem
      result.mem = arm64.MemoryOperand(
        base: baseReg,
        offset: baseOffset + int32(fieldOffset),
        hasIndex: baseHasIndex,
        index: baseIndex,
        shift: baseShift
      )
      result.typ = Type(kind: TypeKind.PtrT, base: fieldType)
    elif t == AtTagId:
      # (at <base> <index>) folds to an LDR/STR scaled-index operand, or
      # (at <base> <index> <scratch-reg>): the element stride isn't an LDR scale
      # (a multi-dimensional array's outer dimension), so arkham hands us a scratch
      # register and WE compute `base + index*stride` into it — the stride comes
      # from the element type (typed layer), the scratch from arkham (regalloc).
      # `into` bounds the node so the optional third operand reads safely.
      into n:
        var baseOp = parseOperandA64(n, ctx)
        var indexOp = parseOperandA64(n, ctx)
        if not isIntegerType(indexOp.typ):
          error("Array index must be integer type, got " & $indexOp.typ, n)
        var elemType: Type
        var baseReg: arm64.Register
        var baseOffset: int32 = 0
        var baseIndex: arm64.Register
        var baseShift: int = 0
        var baseHasIndex = false
        if baseOp.typ.kind == TypeKind.AptrT:
          elemType = resolvedBase(baseOp.typ, ctx, n)
          baseReg = baseOp.reg
        elif baseOp.typ.kind == TypeKind.PtrT and
             resolvedBase(baseOp.typ, ctx, n).kind == TypeKind.ArrayT:
          # (at <base> index) where <base> is a pointer-to-array address
          # `(cast (ptr (array elem N)) base)` — how arkham reaches a global array
          # or a deref'd array field. A nested `(at …)` base carries its own base
          # register + offset (+ a folded index), all folded on here.
          elemType = resolvedBase(baseOp.typ, ctx, n).elem
          if baseOp.kind == okMem:
            baseReg = baseOp.mem.base
            baseOffset = baseOp.mem.offset
            baseIndex = baseOp.mem.index
            baseShift = baseOp.mem.shift
            baseHasIndex = baseOp.mem.hasIndex
          else:
            baseReg = baseOp.reg
        elif baseOp.kind == okMem and baseOp.typ.kind == TypeKind.ArrayT:
          elemType = baseOp.typ.elem
          baseReg = baseOp.mem.base
          baseOffset = baseOp.mem.offset
        elif baseOp.kind == okMem and baseOp.typ.kind == TypeKind.StackOffT and
             baseOp.typ.offType.kind == TypeKind.ArrayT:
          # a stack-resident array: unwrap the StackOffT to its array type
          elemType = baseOp.typ.offType.elem
          baseReg = baseOp.mem.base
          baseOffset = baseOp.mem.offset
        else:
          error("at requires aptr, pointer-to-array, or stack array, got " & $baseOp.typ, n)

        var hasScratch = false
        var scratchReg: arm64.Register
        if n.hasMore:
          # The scratch is a raw `(xN)` or — when arkham `rebind`-bound it to a checked
          # name — the variable name; both resolve through parseOperandA64 to a register.
          let scratchOp = parseOperandA64(n, ctx)
          if scratchOp.kind != okReg:
            error("at: 3-operand scratch must be a register", n)
          scratchReg = scratchOp.reg
          hasScratch = true

        if hasScratch:
          # scratch = base + index*stride. arkham only emits this for a register
          # index, so indexOp is in a register; reuse scratch for the stride const.
          if indexOp.kind != okReg:
            error("at: 3-operand form expects a register index", n)
          if baseHasIndex:
            error("at: 3-operand form cannot extend a base that already has an index", n)
          # Disjointness: `scratch==base` is fatal — `emitMul(scratch, index, X16)`
          # writes scratch (== base) before `emitAdd(scratch, base, scratch)` reads the
          # base, dropping it (→ a wild address). This is the arkham "Bug J" class; flag
          # it at assemble time. `scratch==index` IS allowed here (the X16 stride trick
          # keeps the index intact through the multiply — see the note below).
          if scratchReg == baseReg:
            error("at: 3-operand stride scratch aliases the base register (" &
                  $baseReg & ") — the base is clobbered before use (codegen bug)", n)
          let stride = asmSizeOf(elemType)
          # The stride constant goes into the RESERVED assembler scratch X16, NOT the
          # output `scratchReg`: arkham may hand a scratch that ALIASES the index (x86
          # tolerates `scratch==idx`, and under register pressure it can be the only free
          # register). Materializing the stride into `scratchReg` first would clobber the
          # index before the multiply; X16 keeps the index intact, so `scratch==idx` stays
          # correct (`scratch = idx*stride` reads idx, writes scratch). X16/X17 are never
          # allocated by arkham, so this can't collide with base/index/scratch.
          # A power-of-two stride — which every aggregate whose size the layout rounded
          # up is — is a SHIFT, so it needs neither the constant nor the multiply:
          # `lsl scratch, idx, #k` replaces `mov x16,#stride; mul scratch, idx, x16`.
          # This is the 3-operand `(at …)` used for a non-scale element size, i.e. an
          # ADDRESS computation inside a loop, so the pair was paying twice over.
          if stride > 0 and (stride and (stride - 1)) == 0:
            var k = 0'u8
            var t = stride
            while t > 1: (t = t shr 1; inc k)
            if k == 0:
              arm64.emitMov(ctx.buf.data, scratchReg, indexOp.reg)      # stride 1
            else:
              arm64.emitLslImm(ctx.buf.data, scratchReg, indexOp.reg, k)
          else:
            arm64.emitMovImm64(ctx.buf.data, arm64.X16, uint64(stride))
            arm64.emitMul(ctx.buf.data, scratchReg, indexOp.reg, arm64.X16) # scratch = idx*stride
          # scratch = base + that. A SP base (a stack array) needs the EXTENDED-register
          # ADD — the shifted-register `emitAdd` would read register 31 as XZR, not SP,
          # zeroing the base (→ a wild address). Other bases use the plain register ADD.
          if baseReg == arm64.SP:
            arm64.emitAddExtended(ctx.buf.data, scratchReg, baseReg, scratchReg)
          else:
            arm64.emitAdd(ctx.buf.data, scratchReg, baseReg, scratchReg)
          result.kind = okMem
          result.mem = arm64.MemoryOperand(base: scratchReg, offset: baseOffset, hasIndex: false)
        elif indexOp.kind == okImm:
          let offset = indexOp.immVal * asmSizeOf(elemType)
          result.kind = okMem
          result.mem = arm64.MemoryOperand(
            base: baseReg, index: baseIndex, shift: baseShift,
            offset: baseOffset + int32(offset), hasIndex: baseHasIndex)
        elif indexOp.kind == okMem:
          error("Array index cannot be memory operand", n)
        else:
          if baseHasIndex:
            error("at: two register indices cannot fold into one memory operand", n)
          # Disjointness: base and index of the folded `[base + index<<shift]` are two
          # distinct live values (array address vs element index); aliasing them is a
          # codegen bug, so flag it rather than emit a silently-wrong address.
          if indexOp.reg == baseReg:
            error("at: array base and index occupy the same register (" &
                  $baseReg & ") — distinct values aliased (codegen bug)", n)
          let elemSize = asmSizeOf(elemType)
          if elemSize notin [1, 2, 4, 8]:
            error("Element size " & $elemSize & " not a scale and no scratch supplied", n)
          let shift = case elemSize
            of 1: 0
            of 2: 1
            of 4: 2
            of 8: 3
            else: 0
          result.kind = okMem
          result.mem = arm64.MemoryOperand(
            base: baseReg, index: indexOp.reg, shift: shift, offset: baseOffset, hasIndex: true)
        result.typ = Type(kind: TypeKind.PtrT, base: elemType)
        while n.hasMore: skip n
    elif t == LabTagId:
      inc n
      if n.kind != Symbol: error("Expected label usage", n)
      let name = getSym(n)
      let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
      if sym == nil or sym.kind != skLabel: error("Unknown label: " & name, n)
      if sym == ctx.traceSym: ctx.traceUsed = true   # emit the table (appendTraceTable)
      inc n
      result.reg = arm64.X0
      result.label = LabelId(sym.offset)
      result.typ = Type(kind: UIntT, bits: 64)
    elif t == CastTagId:
      inc n
      let castType = parseType(n, ctx.scope, ctx)
      var op = parseOperandA64(n, ctx)
      op.typ = castType
      result = op
    elif t == MemTagId:
      # `into` bounds the cursor to the mem node, so the OPTIONAL index/shift/offset
      # checks below are gated by `hasMore` and never read into the following sibling
      # (there is no ParRi sentinel to stop them otherwise — a register-bound scratch
      # name following a `(mem base)` store dest would otherwise be eaten as an index).
      # Mirrors the x64 `mem` handler.
      into n:
        if n.kind == TagLit and (n.tag == DotTagId or n.tag == AtTagId):
          var addrOp = parseOperandA64(n, ctx)
          if addrOp.kind != okMem:
            error("mem requires address expression", n)
          if addrOp.typ.kind != TypeKind.PtrT:
            error("mem requires pointer type, got " & $addrOp.typ, n)
          result = addrOp
          result.typ = resolvedBase(addrOp.typ, ctx, n)
        else:
          var baseOp = parseOperandA64(n, ctx)
          if baseOp.kind == okImm or baseOp.kind == okMem:
            error("mem base must be a register", n)
          var offset: int32 = 0
          var hasIndex = false
          var indexReg: arm64.Register = arm64.X0
          var shift: int = 0
          if n.hasMore and n.kind == TagLit and n.tag == ArgTagId:
            # (mem (sp) (arg name)) - address of an outgoing stack argument slot
            let argOff = parseOperandA64(n, ctx)
            if argOff.kind != okImm:
              error("(arg ...) in mem must denote a stack argument", n)
            offset = int32(argOff.immVal)
          elif n.hasMore and (n.kind == IntLit or n.kind == Symbol):
            if n.kind == IntLit:
              offset = int32(getInt(n))
              inc n
            elif n.kind == Symbol:
              let indexName = getSym(n)
              let indexSym = lookupWithAutoImport(ctx, ctx.scope, indexName, n)
              if indexSym != nil and indexSym.kind == skVar and indexSym.reg != InvalidTagId:
                hasIndex = true
                indexReg = tagToRegisterA64(indexSym.reg, n)
                inc n
                if n.hasMore and n.kind == IntLit:
                  shift = int(getInt(n))
                  if shift notin [0, 1, 2, 3]:
                    error("mem shift must be 0, 1, 2, or 3", n)
                  inc n
                  if n.hasMore and n.kind == IntLit:
                    offset = int32(getInt(n))
                    inc n
              else:
                error("Expected index register or offset in mem", n)
          result.kind = okMem
          result.mem = arm64.MemoryOperand(
            base: baseOp.reg,
            index: indexReg,
            shift: shift,
            offset: offset,
            hasIndex: hasIndex
          )
          # The deref of `(ptr T)` has type T — no special cases (mirror of the x64 `mem`
          # handler). `memWidthOpc` sizes it from T (a sub-word int/bool → a narrow ldrb/
          # ldrh, e.g. the SSO `(ptr (u 8))` `s[i]` char read; everything ≥8 bytes → a
          # word); `movCompatible` decides whether T can move to/from the chosen register.
          if baseOp.typ != nil and baseOp.typ.kind in {TypeKind.PtrT, TypeKind.AptrT}:
            result.typ = resolvedBase(baseOp.typ, ctx, n)
          else:
            result.typ = Type(kind: IntT, bits: 64)
    elif t == SsizeTagId:
      # `(ssize)` is the frame size, filled in at `finalize` once every `(s)` slot is
      # allocated. The optional `(ssize N)` adds N bytes to THIS site only — the
      # prologue/epilogue use it to fold the 16-byte alignment pad into the frame
      # adjustment instead of emitting a second `sub rsp, 8` / `add rsp, 8`.
      result.kind = okSsize
      result.typ = Type(kind: IntT, bits: 64)
      result.immVal = 0
      inc n
      if n.kind == IntLit:
        result.immVal = n.intVal
        inc n
    elif t == CsizeTagId:
      # (csize) - total bytes reserved for outgoing stack arguments
      if not ctx.inCall:
        error("(csize) can only be used inside a prepare block", n)
      result.kind = okCsize
      result.immVal = int64(ctx.callContext.stackArgSize)
      result.typ = Type(kind: IntT, bits: 64)
      inc n
    elif t == ArgTagId:
      # (arg name [k]) - argument reference inside a prepare block. `into` bounds the
      # cursor to the arg's children so the optional word index `k` (the k-th register
      # of a ≤16B by-value aggregate) is read without leaking the following sibling.
      if not ctx.inCall:
        error("(arg ...) can only be used inside a prepare block", n)
      var argName = SymId(0)
      var wordIdx = 0
      into n:
        if n.kind != Symbol: error("Expected argument name in (arg ...)", n)
        argName = getSymId(n)
        inc n
        if n.hasMore and n.kind == IntLit:
          wordIdx = int(getInt(n))
          inc n
      let paramPtr = findParam(ctx.callContext.typ, argName)
      if paramPtr == nil:
        error("Unknown argument: " & ctx.nameOf(argName), n)
      if paramPtr.typ.isOnStack:
        # Stack argument used as an offset (e.g. inside (mem (sp) (arg name))).
        # The base offset is the running byte position among the stack-passed
        # params; the optional word index `k` selects the k-th eightbyte (8 bytes)
        # of a multi-word stack aggregate so it can be marshalled/read word-by-word.
        var offset = ctx.callContext.stackArgBase   # Win64 extern: above the shadow space
        for p in ctx.callContext.typ.params:
          if p.typ.isOnStack:
            if p.name == argName:
              break
            offset += slots.alignedSize(p.typ)
        result.kind = okImm
        result.argName = argName
        result.immVal = int64(offset + wordIdx * asmWordSize())
        result.typ = paramPtr.typ
      else:
        if wordIdx >= paramPtr.regs.len:
          error("argument word index out of range for " & ctx.nameOf(argName), n)
        result.kind = okArg
        result.argName = argName
        result.reg = tagToRegisterA64(paramPtr.regs[wordIdx], n)
        result.typ =
          if paramPtr.typ.kind in {TypeKind.ObjectT, TypeKind.ArrayT, TypeKind.UnionT}: Type(kind: RegisterT, regBits: 64)
          else: paramPtr.typ
    elif t == ResTagId:
      # (res name) - result reference inside a prepare block (after the call)
      if not ctx.inCall:
        error("(res ...) can only be used inside a prepare block", n)
      inc n
      if n.kind != Symbol: error("Expected result name in (res ...)", n)
      let resName = getSymId(n)
      inc n
      if not ctx.callContext.callEmitted:
        error("(res ...) can only be used after (call) or (extcall)", n)
      let resPtr = findResult(ctx.callContext.typ, resName)
      if resPtr == nil:
        error("Unknown result: " & ctx.nameOf(resName), n)
      if resName in ctx.callContext.resultsSet:
        error("Result already bound: " & ctx.nameOf(resName), n)
      ctx.callContext.resultsSet.incl(resName)
      result.reg = tagToRegisterA64(resPtr.reg, n)
      result.typ = resPtr.typ
    else:
      error("Unexpected operand tag: " & $t, n)
  elif n.kind == IntLit:
    result.kind = okImm
    result.immVal = getInt(n)
    result.typ = Type(kind: IntLitT, bits: 64, litVal: result.immVal)
    inc n
  elif n.kind == Symbol:
    let name = getSym(n)
    let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
    if sym != nil and (sym.kind == skVar or sym.kind == skParam):
      if sym.typ.isOnStack:
        # Return StackOffT - operations like `add` will reject this at type check
        result.kind = okMem
        result.mem = arm64.MemoryOperand(base: arm64.SP, offset: int32(sym.offset))
        result.typ = sym.typ  # Already StackOffT from declaration
        inc n
        return
      elif sym.reg != InvalidTagId:
        result.reg = tagToRegisterA64(sym.reg, n)
        # Reading a register-bound local whose register a prior `(call)` clobbered
        # would read garbage (the value the call overwrote): reject it. The allocator
        # homes cross-call values in callee-saved registers, so this only fires on a
        # code-generator bug — the call-safety guarantee.
        if result.reg in ctx.clobberedA64 and not ctx.lenient:
          error("Access to variable '" & name & "' in register " & $result.reg &
                " which was clobbered by a call", n)
        result.typ = sym.typ
      inc n
    elif sym != nil and sym.kind == skLabel:
      result.reg = arm64.X0
      result.label = LabelId(sym.offset)
      result.typ = Type(kind: UIntT, bits: 64)
      inc n
    elif sym != nil and sym.kind == skRodata:
      if ctx.arch == Arch.A64 and sym.dataConst:
        # A `dataConst` blob lives in writable __DATA (it is rebased at load), so
        # its address is formed like a global's — adrp+add through the gvar path —
        # not as a PC-relative __TEXT label. `sym.size` becomes its __DATA offset
        # once its body is laid out (generateSymbol).
        result.gvarSym = sym
      elif sym.offset == -1:
        # Forward reference - create label now but don't define it yet
        # It will be defined when the rodata is actually written
        let labId = ctx.buf.createLabel()
        sym.offset = int(labId)
        result.label = labId
      else:
        result.label = LabelId(sym.offset)
      result.reg = arm64.X0
      result.typ = Type(kind: UIntT, bits: 64)
      inc n
    elif sym != nil and sym.kind == skGvar:
      # A foreign global is bundled into this same image (see generateSymbol), so
      # it is accessed exactly like a local one — no external linking step.
      # On arm64 the global lives in __DATA/.bss; its address is formed with
      # adrp+add at link time (see AdrA64 + writeMachO). Carry the symbol so its
      # final .bss offset (`sym.size`) is read after all symbols are processed.
      result.gvarSym = sym
      result.reg = arm64.X0
      result.typ = Type(kind: UIntT, bits: 64)
      inc n
    elif sym != nil and sym.kind == skTvar:
      # Thread-local var (macOS/arm64): its address is obtained at run time via
      # the TLV descriptor thunk. Carry the symbol; `adr` lowers the call
      # sequence and leaves the variable's address in x0. It is not a plain
      # memory operand, so it must not be loaded/stored directly.
      result.kind = okLabel
      result.tlvSym = sym
      result.typ = Type(kind: UIntT, bits: 64)
      inc n
    elif sym != nil and sym.kind == skProc:
      # A proc used as a value → its code address: `(adr reg proc)` materializes a
      # function pointer. Same label the proc's definition / a direct `(call)` binds,
      # so it resolves to the proc's entry (in __TEXT, reachable by ADR/PC-relative).
      result.kind = okLabel
      if sym.offset == -1:
        let labId = ctx.buf.createLabel()
        sym.offset = int(labId)
        result.label = labId
      else:
        result.label = LabelId(sym.offset)
      result.typ = Type(kind: UIntT, bits: 64)   # a code pointer
      inc n
    else:
      error("Unknown or invalid symbol: " & name, n)
  else:
    error("Unexpected operand kind", n)

proc parseGprA64(n: var Cursor; ctx: var GenContext): arm64.Register =
  ## Resolve a GPR operand that may be a raw `(xN)` tag OR a register-bound variable
  ## name (a `rebind`-bound scratch / register-local), for instruction handlers that
  ## historically accepted only raw registers. Goes through `parseOperandA64`, so a
  ## raw use of a *bound* register is rejected — the name is the legal spelling.
  let op = parseOperandA64(n, ctx)
  if op.kind != okReg:
    error("Expected a register operand", n)
  result = op.reg

proc parseDestA64(n: var Cursor; ctx: var GenContext): OperandA64 =
  if n.kind == TagLit and rawTagIsA64Reg(n.tag):
    result.reg = parseRegisterA64(n)
    result.typ = Type(kind: RegisterT, regBits: 64)
    if result.reg in ctx.a64RegBindings:
      error("Register " & $result.reg & " is bound to variable '" &
            ctx.a64RegBindings[result.reg] & "', use the variable name instead", n)
  elif n.kind == TagLit and n.tag == ArgTagId:
    # (arg name [k]) as destination - binds a register argument inside a prepare block.
    # `into` bounds the cursor to the arg's children so the optional word index `k` (the
    # k-th register of a ≤16B by-value aggregate) is read without leaking the sibling.
    if not ctx.inCall:
      error("(arg ...) can only be used inside a prepare block", n)
    var argName = SymId(0)
    var wordIdx = 0
    into n:
      if n.kind != Symbol: error("Expected argument name in (arg ...)", n)
      argName = getSymId(n)
      inc n
      if n.hasMore and n.kind == IntLit:
        wordIdx = int(getInt(n))
        inc n
    let paramPtr = findParam(ctx.callContext.typ, argName)
    if paramPtr == nil:
      error("Unknown argument: " & ctx.nameOf(argName), n)
    if paramPtr.typ.isOnStack:
      error("Stack argument '" & ctx.nameOf(argName) & "' cannot be used directly as destination, use (mem (sp) (arg " & ctx.nameOf(argName) & "))", n)
    # Track once per name (on word 0) so the missing-arg check passes; allow later words.
    if wordIdx == 0:
      if argName in ctx.callContext.argsSet:
        error("Argument already set: " & ctx.nameOf(argName), n)
      ctx.callContext.argsSet.incl(argName)
    if wordIdx >= paramPtr.regs.len:
      error("argument word index out of range for " & ctx.nameOf(argName), n)
    result.kind = okArg
    result.argName = argName
    result.reg = tagToRegisterA64(paramPtr.regs[wordIdx], n)
    result.typ =
      if paramPtr.typ.kind in {TypeKind.ObjectT, TypeKind.ArrayT, TypeKind.UnionT}: Type(kind: RegisterT, regBits: 64)
      else: paramPtr.typ
  elif n.kind == TagLit and (n.tag == MemTagId or n.tag == DotTagId or n.tag == AtTagId):
    let op = parseOperandA64(n, ctx)
    if op.kind != okMem:
      error("Expected memory destination", n)
    result = op
  elif n.kind == Symbol:
    let name = getSym(n)
    let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
    if sym != nil and (sym.kind == skVar or sym.kind == skParam):
      if sym.typ.isOnStack:
        # Return StackOffT - operations like `add` will reject this at type check
        result.kind = okMem
        result.mem = arm64.MemoryOperand(base: arm64.SP, offset: int32(sym.offset))
        result.typ = sym.typ  # Already StackOffT from declaration
        inc n
        return
      elif sym.reg != InvalidTagId:
        result.reg = tagToRegisterA64(sym.reg, n)
        result.typ = sym.typ
        ctx.clobberedA64.excl(result.reg)   # writing a fresh value un-clobbers it
      else:
        error("Variable has no location", n)
      inc n
    elif sym != nil and sym.kind == skTvar:
      # A thread-local var cannot be a direct destination on arm64/macOS: take its
      # address with `(adr (x0) tv)` first, then store through `(mem (x0))`.
      error("Cannot store directly to thread-local '" & name &
            "'; use (adr (x0) " & name & ") then (mem (x0))", n)
    else:
      error("Expected variable or register as destination", n)
  else:
    error("Expected destination", n)

proc parse3OperandsA64(n: var Cursor; ctx: var GenContext; opName: string):
                      tuple[rd, rn: arm64.Register; rm: OperandA64; dstTyp: Type] =
  ## Parse the operands of a 3-operand instruction `(op3 D A B)` → `D = A op B`.
  ## `D` and `A` are registers (`A` is a still-live source read without a prior
  ## `mov D, A`); `B` is the folded operand (register or immediate). Fixed arity, so
  ## no boundary peeking — the reader consumes exactly three operands.
  let dest = parseDestA64(n, ctx)
  if dest.kind == okMem: error(opName & " destination cannot be memory", n)
  let a = parseOperandA64(n, ctx)
  if a.kind != okReg: error(opName & " first source must be a register", n)
  result = (dest.reg, a.reg, parseOperandA64(n, ctx), dest.typ)

proc genPrepareA64(n: var Cursor; ctx: var GenContext) =
  ## Handle (prepare target ... (call) ...) or (prepare target ... (extcall) ...)
  ## The prepare block sets up a call context for type checking and argument tracking.
  var hdr = n
  inc hdr                    # peek at the target symbol (does not advance n)
  if hdr.kind != Symbol: error("Expected proc symbol or type, got " & $hdr.kind, hdr)
  let name = getSym(hdr)
  let sym = lookupWithAutoImport(ctx, ctx.scope, name, hdr)

  let outerCall = ctx.callContext            # restored at the end — see genPrepareX64
  # `> stackArgBase`, not `> 0`: the base is Win64 shadow space, which the CALLEE
  # writes after the call, so two nested calls never contend for it. Genuine stack
  # ARGUMENTS are the conflict — the outer call has already placed some in the one
  # outgoing area the inner call is about to reuse.
  if outerCall.state != CallContextState.Disabled and
     outerCall.stackArgSize > outerCall.stackArgBase:
    error("Nested prepare blocks are not allowed when the outer call passes arguments " &
          "on the stack: both would write the one outgoing argument area", hdr)
  ctx.callContext = CallContext(
    state: CallContextState.NormalCall,
    target: name,
    argsSet: initHashSet[SymId](),
    resultsSet: initHashSet[SymId](),
    callEmitted: false
  )

  if sym == nil:
    error("Unknown symbol: " & name, hdr)
  elif sym.kind == skProc:
    # A foreign proc is bundled into this image and called directly (see
    # generateSymbol); only genuine `extproc` externals use the IAT/extcall path.
    ctx.callContext.typ = sym.typ
  elif sym.kind == skSysProc:
    # A Linux syscall with a full proctype: args land in the syscall ABI registers
    # the proctype names (x0–x5); the invocation marker is `(svc 0)`, which
    # `genSyscallMarkerA64` turns into `mov x8,NR; svc 0`. No `bl`/address.
    ctx.callContext.typ = sym.typ
    ctx.callContext.isSyscall = true
    ctx.callContext.syscallNr = sym.offset
  elif sym.kind in {skGvar, skTvar, skVar, skParam} and sym.typ.kind == ProcT:
    # Indirect call through a function-pointer variable: its proctype IS the
    # signature, so arg/result checking and stack layout proceed exactly as for a
    # direct call; only `(call)` differs (it loads the pointer and calls through it).
    ctx.callContext.typ = sym.typ
    ctx.callContext.indirect = true
  elif sym.kind == skExtProc:
    ctx.callContext.state = CallContextState.ExternalCall
    for i, ext in ctx.extProcs:
      if ext.name == name:
        ctx.callContext.extProcIdx = i
        break
  else:
    error("Expected proc symbol, got " & $sym.kind, hdr)

  # Compute stack argument size (only for internal procs)
  if ctx.callContext.state == CallContextState.NormalCall:
    ctx.callContext.stackArgSize = computeStackArgSize(ctx.callContext.typ)
    # Fixed-frame soundness (AArch64): this call's outgoing stack args occupy
    # `[sp, sp+stackArgSize)`, the region `scanStackArgArea` reserved at the frame bottom.
    # If the pre-scan didn't see this target (an indirect call through a not-yet-declared
    # local fn-ptr), the reservation may be too small — fail loudly rather than let the
    # args overwrite a local `(s)` slot.
    if ctx.callContext.stackArgSize > ctx.reservedArgArea:
      error("outgoing stack-argument area (" & $ctx.callContext.stackArgSize &
            " bytes) exceeds the reserved frame area (" & $ctx.reservedArgArea &
            " bytes); call target not visible to the frame pre-scan", hdr)

  # Consume the prepare node: skip the (already-read) target, then generate each
  # instruction. `into` bounds the loop to this node (no ParRi sentinel exists).
  into n:
    skip n                   # the target symbol
    while n.hasMore:
      genInstA64(n, ctx)

  # Verify call was emitted and all bindings are done
  if ctx.callContext.state == CallContextState.NormalCall:
    for param in ctx.callContext.typ.params:
      if not param.typ.isOnStack and param.name notin ctx.callContext.argsSet:
        error("Missing argument: " & ctx.nameOf(param.name), hdr)

    if not ctx.callContext.isTailcall:
      # A tail call binds no result: the callee's return value IS this proc's, and
      # it is already in the return register when the callee's own `ret` runs.
      for res in ctx.callContext.typ.results:
        if res.name notin ctx.callContext.resultsSet:
          error("Missing result binding: " & ctx.nameOf(res.name), hdr)

    if not ctx.callContext.callEmitted:
      error("Missing (call), (tailcall) or (extcall) in prepare block", hdr)
  else:
    if not ctx.callContext.callEmitted:
      error("Missing (extcall) in prepare block", hdr)

  # Resume the enclosing call, if this prepare was nested inside one. arkham emits that
  # for an argument that is itself a call — `f(g(x))`, which hexer leaves unflattened in
  # a global's initializer expression. The inner call completes (its result lands in the
  # return register) before any of the outer call's `(arg …)` bindings that follow it.
  ctx.callContext = outerCall
  if outerCall.state == CallContextState.Disabled:
    ctx.callContext.state = CallContextState.Disabled

const A64CallClobbers = {arm64.X0 .. arm64.X15}
  ## The caller-saved GPRs a call destroys (AAPCS64; x16/x17 are assembler veneers
  ## never bound to a variable, x18 is platform-reserved). A bound value living in one
  ## of these across a `(call)`/`(extcall)` is gone — exactly what arkham's allocator
  ## avoids by homing cross-call values in callee-saved x19–x28, and what the clobber
  ## check guards against. Matches arkham's emitted `(clobber …)` (`ConvClobbersGpr`).

proc callClobbersA64(ctx: GenContext): set[arm64.Register] =
  ## What the callee currently being `prepare`d actually destroys. The signature's
  ## own `(clobber …)` wins when it declared one: arkham emits an EMPTY list for a
  ## `(attr "noreturn")` callee (panic, raiseAssert, the bounds-check failure path),
  ## because a call that never returns has no "afterwards" in which a caller could
  ## observe the damage — and taking that at face value is what lets the allocator
  ## keep a value in a caller-saved register across a cold guard instead of forcing
  ## it onto a callee-saved home with the prologue push/pop that entails. A
  ## signature that declared nothing at all falls back to the full volatile set.
  let t = ctx.callContext.typ
  if t != nil and t.kind == ProcT and t.hasClobberDecl: t.clobbersA64
  else: A64CallClobbers

proc genCallMarkerA64(n: var Cursor; ctx: var GenContext) =
  ## Handle (call) marker inside a prepare block - emits the actual call instruction
  if not ctx.inCall:
    error("(call) can only be used inside a prepare block", n)

  if ctx.callContext.callEmitted:
    error("Multiple (call) instructions in prepare block", n)
  if ctx.callContext.state == CallContextState.ExternalCall:
    error("Use (extcall) for external procs, not (call)", n)

  let sym = lookupWithAutoImport(ctx, ctx.scope, ctx.callContext.target, n)
  ctx.clobberedA64.incl callClobbersA64(ctx)   # what the callee declares it destroys

  if ctx.callContext.indirect:
    # Indirect call through a function-pointer variable: load the pointer into x16
    # (IP0 — caller-saved, not an argument register, so the prepared args in x0–x7
    # are untouched) and `blr` through it. A global's address is formed with adrp+add
    # (recorded as a gvar site and patched once the data layout is known), exactly
    # like a `(lea reg gvar)`; then the pointer value is loaded and called.
    if sym.kind in {skVar, skParam} and sym.reg != InvalidTagId:
      # A function pointer held directly in a REGISTER (vtable-method load / reg-resident
      # `var f: proc`): the register holds the code address itself → `blr reg`, no load.
      arm64.emitBlr(ctx.buf.data, tagToRegisterA64(sym.reg, n))
    elif sym.kind == skGvar:
      let pos = ctx.buf.data.getCurrentPosition()
      arm64.emitAdrpAddGvar(ctx.buf.data, arm64.X16)            # x16 = &fnptr
      ctx.gvarSites.add (pos, sym)
      arm64.emitLdr(ctx.buf.data, arm64.X16, arm64.X16, 0'i32)  # x16 = fnptr
      arm64.emitBlr(ctx.buf.data, arm64.X16)
    else:
      error("Indirect call through unsupported function-pointer location: " &
            $sym.kind, n)
    ctx.callContext.callEmitted = true
    inc n
    return

  var labId: LabelId
  if sym.offset == -1:
    labId = ctx.buf.createLabel()
    sym.offset = int(labId)
  else:
    labId = LabelId(sym.offset)

  ctx.buf.emitBL(labId)
  ctx.callContext.callEmitted = true

  inc n

proc genTailcallMarkerA64(n: var Cursor; ctx: var GenContext) =
  ## `(tailcall)` — the `(call)` marker's no-link twin. Same prepared arguments,
  ## same clobber declaration, `b`/`br` instead of `bl`/`blr`: control leaves this
  ## proc for good, so the callee returns to OUR caller and its `ret` is ours.
  ##
  ## The frame is already gone. arkham tears it down between the last argument
  ## store and this marker — the teardown touches only SP and callee-saved
  ## registers, never x0–x7 — so nothing here may address a stack slot, which is
  ## also why arkham refuses to form a tail call that needs stack arguments.
  if not ctx.inCall:
    error("(tailcall) can only be used inside a prepare block", n)
  if ctx.callContext.callEmitted:
    error("Multiple call instructions in prepare block", n)
  let sym = lookupWithAutoImport(ctx, ctx.scope, ctx.callContext.target, n)
  ctx.clobberedA64.incl callClobbersA64(ctx)
  ctx.callContext.isTailcall = true
  if ctx.callContext.indirect:
    # An INDIRECT tail call would have to survive the `(popframe)` that precedes
    # it, and the pointer is exactly what does not: it sits in a register the
    # prologue saved, so restoring the frame restores the caller's value over it.
    # Staging it in x16 first is possible but not expressible here — `(popframe)`
    # is already emitted by the time this marker is read — so the backend must not
    # form one, and this says so loudly rather than branching to whatever the
    # caller happened to leave in that register.
    error("indirect tail call: the target register does not survive (popframe)", n)
  var labId: LabelId
  if sym.offset == -1:
    labId = ctx.buf.createLabel()
    sym.offset = int(labId)
  else:
    labId = LabelId(sym.offset)
  ctx.buf.emitB(labId)
  ctx.callContext.callEmitted = true
  inc n

proc genSyscallMarkerA64(n: var Cursor; ctx: var GenContext) =
  ## `(svc 0)` inside a `(prepare <syproc> …)` block: the syscall counterpart of
  ## `(call)`. The args are already in x0–x5 (the syproc's params); this loads the
  ## number into x8 and traps. Unlike a `bl`, a Linux/AArch64 `svc` preserves every
  ## register except x0 (the result), so only x0 is marked clobbered.
  if ctx.callContext.callEmitted:
    error("Multiple call/syscall instructions in prepare block", n)
  intoOperands n:                        # `(svc 0)` — consume and ignore the immediate
    skip n
    while n.hasMore: skip n
  arm64.emitMovImm64(ctx.buf.data, arm64.X8, uint64(ctx.callContext.syscallNr))
  arm64.emitSvc(ctx.buf.data, 0'u16)
  ctx.clobberedA64.incl arm64.X0
  ctx.callContext.callEmitted = true

proc genExtcallA64(n: var Cursor; ctx: var GenContext) =
  ## Handle (extcall) marker inside a prepare block - emits external call
  if not ctx.inCall:
    error("(extcall) can only be used inside a prepare block", n)

  if ctx.callContext.callEmitted:
    error("Multiple call instructions in prepare block", n)
  if ctx.callContext.state == CallContextState.NormalCall:
    error("Use (call) for internal procs, not (extcall)", n)
  ctx.clobberedA64.incl callClobbersA64(ctx)   # what the callee declares it destroys

  # Record call site and emit BL (will be patched to point to stub)
  let callPos = ctx.buf.data.len
  ctx.extProcs[ctx.callContext.extProcIdx].callSites.add callPos
  ctx.buf.data.addUint32(0x94000000'u32)  # BL placeholder

  ctx.callContext.callEmitted = true

  inc n

proc genIteA64(n: var Cursor; ctx: var GenContext) =
  inc n
  let lElse = ctx.buf.createLabel()
  let lEnd = ctx.buf.createLabel()
  let oldClobbered = ctx.clobbered
  let oldClobberedA64 = ctx.clobberedA64
  if n.kind == Symbol:
    let name = getSym(n)
    let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
    if sym == nil or sym.kind != skCfvar: error("Expected cfvar in ite condition: " & name, n)
    if sym.used:
      error("Control flow variable '" & name & "' used more than once", n)
    sym.used = true
    inc n
    ctx.buf.emitB(lElse)
    ctx.buf.defineLabel(LabelId(sym.offset))
  elif n.kind == TagLit:
    # Hardware condition - ARM64 uses flags from CMP
    let flagTag = tagToX64Flag(n.tag)
    inc n

    # Emit branch to else if condition is NOT met (inverted condition)
    case flagTag
    of ZfO: ctx.buf.emitBne(lElse)   # if ZF set wanted, jump to else if ZF clear
    of NzO: ctx.buf.emitBeq(lElse)   # if ZF clear wanted, jump to else if ZF set
    else: error("Unsupported ARM64 flag condition: " & $flagTag, n)
  else:
    error("Expected cfvar or flag condition in ite", n)
  genStmt(n, ctx)
  let thenClobbered = ctx.clobbered
  let thenClobberedA64 = ctx.clobberedA64
  ctx.buf.emitB(lEnd)
  ctx.clobbered = oldClobbered
  ctx.clobberedA64 = oldClobberedA64
  ctx.buf.defineLabel(lElse)
  genStmt(n, ctx)
  let elseClobbered = ctx.clobbered
  let elseClobberedA64 = ctx.clobberedA64
  ctx.buf.defineLabel(lEnd)
  # A register clobbered on EITHER branch is clobbered after the merge.
  ctx.clobbered = thenClobbered + elseClobbered
  ctx.clobberedA64 = thenClobberedA64 + elseClobberedA64

proc genLoopA64(n: var Cursor; ctx: var GenContext) =
  inc n
  # Bare infinite-loop form `(loop (stmts …))` — the back-edge is emitted INTERNALLY here,
  # so no backward branch reaches the input; the body carries a FORWARD branch to a break/
  # exit label defined AFTER the loop. This is the form arkham emits for every loop (mirrors
  # the x64 `genLoopX64`). The legacy `(loop <pre> <condflag> <body>)` form below is unused.
  if atTag(n, StmtsTagId):
    let lStart = ctx.buf.createLabel()
    ctx.buf.defineLabel(lStart)
    genStmt(n, ctx)                 # the body (contains the forward break/exit branch)
    ctx.buf.emitB(lStart)           # the loop back-edge — emitted by nifasm, not the input
    return

  genStmt(n, ctx)
  let lStart = ctx.buf.createLabel()
  let lEnd = ctx.buf.createLabel()
  ctx.buf.defineLabel(lStart)
  if n.kind != TagLit: error("Expected condition", n)
  let condTag = n.tag
  inc n

  # ARM64 loop conditions - exit loop if condition is NOT met
  let loopFlagTag = tagToX64Flag(condTag)
  case loopFlagTag
  of ZfO: ctx.buf.emitBne(lEnd)   # if ZF set wanted, exit if ZF clear
  of NzO: ctx.buf.emitBeq(lEnd)   # if ZF clear wanted, exit if ZF set
  else: error("Unsupported ARM64 loop condition: " & $loopFlagTag, n)

  genStmt(n, ctx)
  ctx.buf.emitB(lStart)
  ctx.buf.defineLabel(lEnd)

proc genJtrueA64(n: var Cursor; ctx: var GenContext) =
  let start = n
  inc n
  var jumpTarget: LabelId
  var firstCfvar = true
  while n.kind == Symbol:
    let name = getSym(n)
    let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
    if sym == nil: error("Unknown cfvar: " & name, n)
    if sym.kind != skCfvar: error("Symbol is not a cfvar: " & name, n)
    if firstCfvar:
      jumpTarget = LabelId(sym.offset)
      firstCfvar = false
    inc n
  if firstCfvar: error("jtrue requires at least one cfvar", start)
  ctx.buf.emitB(jumpTarget)

proc genKillA64(n: var Cursor; ctx: var GenContext) =
  inc n
  if n.kind != Symbol: error("Expected symbol to kill", n)
  let name = getSym(n)
  let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
  if sym == nil: error("Unknown variable to kill: " & name, n)
  if sym.typ.isOnStack:
    ctx.slots.killSlot(sym.offset, sym.typ)
  elif sym.reg != InvalidTagId:
    if isA64FpRegTag(sym.reg):
      ctx.a64FRegBindings.del(tagToFloatRegA64(sym.reg))
    else:
      ctx.a64RegBindings.del(tagToRegisterA64(sym.reg, n))
  ctx.scope.undefine(sym.name)
  inc n

proc bindRegA64(ctx: var GenContext; name: string; typ: Type; regTag: TagEnum;
                reg: arm64.Register) =
  ## Bind physical register `reg` to the typed name `name`, *killing its prior tenant
  ## first* (the previous binding's name is undefined, so a later use of a value
  ## wrongly left in that register becomes an "Unknown symbol" error rather than a
  ## silent clobber). The "(re)bind implies a kill of the prior tenant" rule shared by
  ## `rebind` and `withreg`. Mirrors x64's `bindRegX64`.
  if reg in ctx.a64RegBindings:
    ctx.scope.undefine(ctx.symIdOf(ctx.a64RegBindings[reg]))
    ctx.a64RegBindings.del(reg)
  ctx.clobberedA64.excl(reg)   # a fresh binding abandons a prior call's clobber (see bindRegX64)
  let sym = Symbol(name: ctx.symIdOf(name), kind: skVar, typ: typ)
  sym.reg = regTag
  ctx.a64RegBindings[reg] = name
  ctx.scope.define(sym)

proc bindFRegA64(ctx: var GenContext; name: string; typ: Type; regTag: TagEnum;
                 reg: arm64.FloatRegister) =
  ## The SIMD twin of `bindRegA64`: bind v-register `reg` to the typed float name
  ## `name`, killing its prior tenant first. The binding's type carries the precision
  ## (`(f 32)`/`(f 64)`) so a *named* use recovers s/d. Used for float register locals
  ## and float scratch temps.
  if reg in ctx.a64FRegBindings:
    ctx.scope.undefine(ctx.symIdOf(ctx.a64FRegBindings[reg]))
    ctx.a64FRegBindings.del(reg)
  let sym = Symbol(name: ctx.symIdOf(name), kind: skVar, typ: typ)
  sym.reg = regTag
  ctx.a64FRegBindings[reg] = name
  ctx.scope.define(sym)

proc parseRebindHeaderA64(n: var Cursor; ctx: var GenContext):
                          tuple[name: string; isFp: bool; reg: arm64.Register;
                                freg: arm64.FloatRegister] =
  ## Parse `:name TYPE (reg)` (cursor past the rebind/withreg tag, inside the node)
  ## and establish the binding. Shared by `rebind` and `withreg`. The register may be
  ## a GPR (`(xN)`) or — for a float binding — a v-register (`(dN)`/`(sN)`).
  if n.kind != SymbolDef: error("Expected name for rebind/withreg", n)
  let name = symName(n); inc n
  let typ = parseType(n, ctx.scope, ctx)
  if isA64FpRegOperand(n):
    let regTag = n.tag
    let freg = tagToFloatRegA64(regTag)
    inc n
    bindFRegA64(ctx, name, typ, regTag, freg)
    result = (name, true, arm64.Register(0), freg)
  elif n.kind == TagLit and rawTagIsA64Reg(n.tag):
    let regTag = n.tag
    let reg = tagToRegisterA64(regTag, n)
    inc n
    bindRegA64(ctx, name, typ, regTag, reg)
    result = (name, false, reg, arm64.FloatRegister(0))
  else:
    error("Expected a register for rebind/withreg", n)

proc genRebindA64(n: var Cursor; ctx: var GenContext) =
  ## `(rebind :name TYPE (reg))` — bind `reg` to `name`, killing its prior tenant. The
  ## binding lives until an explicit `kill`, the next `rebind` of `reg`, or proc end
  ## (`a64RegBindings` is reset per proc).
  into n:
    discard parseRebindHeaderA64(n, ctx)

proc genWithregA64(n: var Cursor; ctx: var GenContext) =
  ## `(withreg :name TYPE (reg) body…)` — a block-scoped `rebind`: the binding is
  ## auto-killed at the end of the body, in addition to killing `reg`'s prior tenant.
  into n:
    let h = parseRebindHeaderA64(n, ctx)
    while n.hasMore: genInstA64(n, ctx)
    if h.isFp:
      if ctx.a64FRegBindings.getOrDefault(h.freg, "") == h.name:
        ctx.a64FRegBindings.del(h.freg)
    elif ctx.a64RegBindings.getOrDefault(h.reg, "") == h.name:
      ctx.a64RegBindings.del(h.reg)
    ctx.scope.undefine(ctx.symIdOf(h.name))

proc memWidthOpc(typ: Type; isLoad: bool): tuple[size, opc: int] =
  ## Access width (0=byte,1=half,2=word,3=dword) and the load/store `opc` for a
  ## typed memory operand. A `(mem (dot …))` / `(mem (at …))` carries the field /
  ## element type, so a narrow integer load sign-/zero-extends and a narrow store
  ## writes only its low bits. Anything non-integer (pointer, raw `(mem reg)`) is a
  ## full 64-bit access.
  ##
  ## A STACK SLOT is its content type behind a `(stackoff …)` wrapper, so unwrap it
  ## and size the access by what the slot HOLDS. A slot always occupies 8 bytes
  ## (`allocSlotUp` rounds every footprint up to the granularity), so this is not
  ## about layout — it is what makes a narrow local's home behave like the variable
  ## it is: `strb` in, `ldrsb`/`ldrb` out. Reading one as a 64-bit cell instead
  ## returns the upper seven bytes as well, which for a local whose address escaped
  ## into a callee holding `ptr int8` is whatever was there before.
  var bits = 64
  var signed = false
  if typ != nil:
    var t = typ
    if t.kind == StackOffT and t.offType != nil: t = t.offType
    case t.kind
    of IntT: bits = t.bits; signed = true         # `(i N)` (and `(c N)` chars)
    of UIntT: bits = t.bits
    of BoolT: bits = 8
    else: bits = 64                                # PtrT / raw mem / aggregate
  let size = case bits
    of 8: 0
    of 16: 1
    of 32: 2
    else: 3
  let opc = if not isLoad: 0
            elif size == 3: 1                      # 64-bit: plain load, no extend
            elif signed: 2                         # LDRSB/LDRSH/LDRSW → 64-bit
            else: 1                                # LDRB/LDRH/LDR(W) zero-extend
  (size, opc)

proc checkForwardJump(ctx: GenContext; label: LabelId; n: Cursor) =
  ## Enforce the finalir invariant: every `jmp`/`jcc`/`b`/`bcc` must target a label
  ## that is not yet defined (a forward jump). A back-edge to an already-defined local
  ## label is forbidden — loops must be structured as `(loop …)`, whose back-edge is
  ## emitted internally (bypassing this check). Only *local* labels are tracked
  ## (`ctx.definedLabels`), so branches/tail-calls to proc/rodata/gvar targets — which
  ## are never added — are never flagged.
  if ctx.lenient: return    # ported code keeps its original jump structure
  if int(label) in ctx.definedLabels:
    error("backward jump to an already-defined label is forbidden; " &
          "express the back-edge as a (loop …) instead", n)

proc emitAddOffsetA64(ctx: var GenContext; rd, rn: arm64.Register; offset: int64;
                      scratch: arm64.Register) =
  ## `rd = rn + offset`, synthesizing through `scratch` (a reserved assembler
  ## register, X16/X17) when the offset exceeds ADD's 12-bit immediate field.
  ## The old `uint16(offset)` call sites silently MIS-ENCODED 4096..65535 (the
  ## immediate overflowed into the shift/opcode bits).
  if offset >= 0 and offset <= 4095:
    arm64.emitAddImm(ctx.buf.data, rd, rn, uint16(offset))
  else:
    arm64.emitMovImm64(ctx.buf.data, scratch, cast[uint64](offset))
    if rn == arm64.SP:
      arm64.emitAddExtended(ctx.buf.data, rd, rn, scratch)
    else:
      arm64.emitAdd(ctx.buf.data, rd, rn, scratch)

proc a64FpMemBase(ctx: var GenContext; m: arm64.MemoryOperand;
                  single: bool): (arm64.Register, int32) =
  ## Reduce an FP load/store's memory operand to a (base, offset) pair the scaled
  ## unsigned-offset FP form can actually encode.
  ##
  ## That form has NO index register and only a `0..0xFFF` *scaled* displacement,
  ## while `(at …)` hands us `base + index<<shift (+ offset)` and a big frame hands
  ## us an offset past the field. Both fold into the reserved X16 veneer (arkham
  ## never allocates X16/X17), leaving the access itself a plain `[X16, #0]`.
  ## Before this, an INDEX was silently dropped — `powtens[i]` read `powtens[0]`
  ## for every i — and a large offset raised "FP LDR offset out of range".
  let scale = if single: 4'i32 else: 8'i32
  if not m.hasIndex and (m.offset mod scale) == 0 and
     m.offset >= 0 and (m.offset div scale) <= 0xFFF:
    return (m.base, m.offset)
  if m.hasIndex:
    # A SP base needs the EXTENDED-register ADD: the shifted form reads reg 31 as
    # XZR, not SP (same rule as `lea`).
    if m.base == arm64.SP:
      arm64.emitAddExtended(ctx.buf.data, arm64.X16, m.base, m.index, uint8(m.shift))
    else:
      arm64.emitAddShifted(ctx.buf.data, arm64.X16, m.base, m.index, uint8(m.shift))
    if m.offset != 0:
      emitAddOffsetA64(ctx, arm64.X16, arm64.X16, m.offset, arm64.X17)
  else:
    emitAddOffsetA64(ctx, arm64.X16, m.base, m.offset, arm64.X17)
  result = (arm64.X16, 0'i32)

proc a64IntMemBase(ctx: var GenContext; m: arm64.MemoryOperand;
                   size: int): arm64.MemoryOperand =
  ## Reduce an integer load/store's memory operand to one the register-offset form can
  ## actually encode.
  ##
  ## `[Xn, Xm, LSL #k]` has a single SCALE bit, and it means "shift by the ACCESS
  ## width's log2" — it is not a general shift amount. So the only strides that form
  ## can say are 1 (S=0) and the transfer size itself (S=1). `(at …)` hands us the
  ## ELEMENT stride, which is the same number only while the access IS the element;
  ## an enclosing `(dot …)` narrows it, and `(dot (at arrayOfTuples i) fld)` then wants
  ## stride 8 with a 4-byte load. That was emitted as `LSL #2` — silently reading
  ## element `i/2` — and as `LSL #0` for a `bool` field, reading element `i/8`. It cost
  ## a self-hosted hexer its `processMethods` loop: a `seq[(SymId, bool)]` walked at a
  ## 4-byte stride visited elements 0, 2, 2, 2, … and handed `getOrQuit` a key that was
  ## half a tuple.
  ##
  ## When the stride is not expressible, compute `base + index<<shift (+ offset)` into
  ## the reserved X16 veneer and access `[X16, #0]` — what `a64FpMemBase` and `lea`
  ## already do for the same reason. X16/X17 are never allocated by arkham.
  result = m
  if not m.hasIndex: return
  if m.shift == 0 or m.shift == size: return    # the S bit says what we mean
  if m.base == arm64.SP:
    # A SP base needs the EXTENDED-register ADD; the shifted form reads reg 31 as XZR.
    arm64.emitAddExtended(ctx.buf.data, arm64.X16, m.base, m.index, uint8(m.shift))
  else:
    arm64.emitAddShifted(ctx.buf.data, arm64.X16, m.base, m.index, uint8(m.shift))
  if m.offset != 0:
    emitAddOffsetA64(ctx, arm64.X16, arm64.X16, m.offset, arm64.X17)
  result = arm64.MemoryOperand(base: arm64.X16, offset: 0, hasIndex: false)

proc a64CondOf(inst: A64Inst): arm64.Condition =
  ## The condition code baked into a `csel*`/`cset*` mnemonic (same condition
  ## vocabulary as the `b*` branches).
  case inst
  of CseleqA64, CseteqA64: arm64.CondEQ
  of CselneA64, CsetneA64: arm64.CondNE
  of CselltA64, CsetltA64: arm64.CondLT
  of CselleA64, CsetleA64: arm64.CondLE
  of CselgtA64, CsetgtA64: arm64.CondGT
  of CselgeA64, CsetgeA64: arm64.CondGE
  of CselloA64, CsetloA64: arm64.CondLO
  of CsellsA64, CsetlsA64: arm64.CondLS
  of CselhiA64, CsethiA64: arm64.CondHI
  of CselhsA64, CsethsA64: arm64.CondHS
  else: raiseAssert("not a conditional-select mnemonic: " & $inst)

proc cfiStep(ctx: var GenContext; cfaDelta: int32;
             savedRegs: openArray[int32] = []; ssizeSlot = false;
             floats = false) =
  ## Record one prologue instruction's effect on the unwind state. Called from
  ## the handlers that emit a push / a pair-store / the frame `sub`, and only
  ## while `inPrologue` — see `genInst` for what ends that run.
  ##
  ## `savedRegs` are in STORE order: the first lands at the new bottom of the
  ## frame (CFA − the offset this step establishes), each next one 8 bytes above.
  ## That one rule covers both a single `push` and a `stp` pair.
  ##
  ## `ssizeSlot` marks the frame `sub`, whose immediate nifasm only knows once
  ## the proc's slots are laid out; `pass2Proc` fills the CFA offset in then.
  if ctx.unwind.len == 0: return
  ctx.cfaOff += cfaDelta
  var saves: seq[CfiSave] = @[]
  for i in 0 ..< savedRegs.len:
    saves.add CfiSave(reg: savedRegs[i], isFloat: floats,
                      cfaOff: -ctx.cfaOff + int32(8 * i))
  ctx.unwind[^1].steps.add CfiStep(at: ctx.buf.data.len, cfaOff: ctx.cfaOff,
                                   saves: saves, ssizeSlot: ssizeSlot)
  ctx.prologueOp = true

proc genPopframeA64(ctx: var GenContext) =
  ## `(popframe)` — undo this proc's prologue, wherever we are in its body.
  ##
  ## The frame's shape is nifasm's to know, not the backend's: arkham finalizes
  ## `usedCallee`/`hasStackVars` only AFTER it has emitted the body (a register
  ## claimed by a last-resort pick mid-body still adds a prologue pair), so a
  ## teardown written at a mid-body site would have to guess how many pairs to pop
  ## and whether a frame `sub` exists at all. Here neither is a guess: the prologue
  ## has already been assembled and `ctx.unwind[^1].steps` records every one of its
  ## stores, in order, with the registers it saved. Replaying that in reverse is the
  ## epilogue by construction.
  ##
  ## A tail call is the caller of this: arguments in place, frame gone, `b` to the
  ## callee, whose `ret` returns to OUR caller.
  if ctx.unwind.len == 0: return
  let steps = ctx.unwind[^1].steps
  for i in countdown(steps.len - 1, 0):
    let st = steps[i]
    if st.ssizeSlot:
      # The frame `sub`'s twin — same two halves, same patch list, since the size
      # is still unknown until the slots are laid out.
      arm64.emitAddImm(ctx.buf.data, arm64.SP, arm64.SP, 0'u16)
      ctx.ssizePatches.add((ctx.buf.data.len - 4, 0))
      arm64.emitAddImmShifted12(ctx.buf.data, arm64.SP, arm64.SP, 0'u16)
      ctx.ssizePatches.add((ctx.buf.data.len - 4, 0))
    elif st.saves.len == 2:
      # One pair push: `stp a, b, [sp, #-16]!` undone by `ldp a, b, [sp], #16`.
      if st.saves[0].isFloat:
        arm64.emitFldpPost(ctx.buf.data,
                           arm64.FloatRegister(st.saves[0].reg),
                           arm64.FloatRegister(st.saves[1].reg), arm64.SP, 16'i32)
      else:
        arm64.emitLdp(ctx.buf.data,
                      arm64.Register(st.saves[0].reg),
                      arm64.Register(st.saves[1].reg), arm64.SP, 16'i32)

proc genInstA64(n: var Cursor; ctx: var GenContext) =
  if n.kind != TagLit: error("Expected instruction", n)
  let instTag = tagToA64Inst(n.tag)
  let start = n

  let declTag = tagToNifasmDecl(n.tag)
  case declTag
  of CfvarD:
    inc n
    if n.kind != SymbolDef: error("Expected cfvar name", n)
    let name = symName(n)
    inc n
    let cfvarLabel = ctx.buf.createLabel()
    let sym = Symbol(name: ctx.symIdOf(name), kind: skCfvar, typ: Type(kind: BoolT), offset: int(cfvarLabel), used: false)
    ctx.scope.define(sym)
    return

  of VarD:
    inc n
    if n.kind != SymbolDef: error("Expected var name", n)
    let name = symName(n)
    inc n
    var reg = InvalidTagId
    var onStack = false
    var slotAlign = asmWordSize()
    if n.kind == TagLit:
      let locTag = n.tag
      if rawTagIsA64Reg(locTag):
        # Check for reserved registers (x16/x17 are reserved for assembler scratch)
        let regTag = tagToA64Reg(locTag)
        if regTag == X16R:
          error("Cannot bind variable to x16 (reserved for assembler use as IP0)", n)
        elif regTag == X17R:
          error("Cannot bind variable to x17 (reserved for assembler use as IP1)", n)
        reg = locTag
        inc n
      elif locTag == STagId:
        onStack = true
        slotAlign = parseSlotAlign(n)         # reads (s (align N)); advances past (s …)
      else:
        error("Expected location", n)
    else:
      error("Expected location", n)
    let baseTyp = parseType(n, ctx.scope, ctx)
    let sym = Symbol(name: ctx.symIdOf(name), kind: skVar)
    if onStack:
      sym.typ = Type(kind: StackOffT, offType: baseTyp)
      sym.offset = ctx.slots.allocSlotUp(baseTyp, slotAlign)
    else:
      sym.typ = baseTyp
      sym.reg = reg
      # Track the register binding so a raw `(xN)` use is rejected; reject reusing a
      # register that still hosts a live variable (kill it first).
      let targetReg = tagToRegisterA64(reg, n)
      if targetReg in ctx.a64RegBindings:
        error("Register " & $targetReg & " is already bound to variable '" &
              ctx.a64RegBindings[targetReg] & "', kill it first before reusing", n)
      ctx.a64RegBindings[targetReg] = name
      # A fresh binding abandons a prior call's clobber — the same rule
      # `bindRegA64` applies to `rebind`. A `(var …)` starts a NEW variable's life
      # in the register, so whatever an earlier call destroyed there is not this
      # variable's value. Without this a local declared after a call, in a
      # caller-saved register, was rejected on its first read.
      ctx.clobberedA64.excl(targetReg)
    ctx.scope.define(sym)
    return
  of NoDecl:
    discard "handle via `case instTag`"
  of TypeD, ProcD, ParamsD, ParamD, ResultD, ClobberD, LenientD,
     ArchD, RodataD, GvarD, TvarD, ImpD, ExtprocD, SyprocD, RegsD:
    raiseAssert("Unhandled declaration tag: " & $declTag)

  # See the same step in `genInstX64`: an overflowing mnemonic's id is a leading
  # child, so skip it once here and every arm's own `inc n` still lands on the
  # first operand.
  if isEscapedTag(n): inc n

  case instTag
  of StmtsA64:
    loopInto n:
      genInstA64(n, ctx)
  of ScopeA64:
    # See `ScopeX64`: reclaimable stack-slot arena for a call's caller-save spills.
    let savedStackSize = ctx.slots.stackSize
    loopInto n:
      genInstA64(n, ctx)
    ctx.slots.maxStackSize = max(ctx.slots.maxStackSize, ctx.slots.stackSize)
    ctx.slots.stackSize = savedStackSize
  of PrepareA64:
    genPrepareA64(n, ctx)
  of CallA64:
    genCallMarkerA64(n, ctx)
  of TailcallA64:
    genTailcallMarkerA64(n, ctx)
  of PopframeA64:
    inc n
    genPopframeA64(ctx)
  of ExtcallA64:
    genExtcallA64(n, ctx)
  of IteA64:
    genIteA64(n, ctx)
  of LoopA64:
    genLoopA64(n, ctx)
  of JtrueA64:
    genJtrueA64(n, ctx)
  of KillA64:
    genKillA64(n, ctx)
  of RebindA64:
    genRebindA64(n, ctx)
  of WithregA64:
    genWithregA64(n, ctx)
  of LabA64:
    inc n
    if n.kind != SymbolDef: error("Expected label name", n)
    let name = symName(n)
    let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
    if sym == nil:
      let labId = ctx.buf.createLabel()
      ctx.scope.define(Symbol(name: ctx.symIdOf(name), kind: skLabel, offset: int(labId)))
      ctx.buf.defineLabel(labId)
      ctx.definedLabels.incl int(labId)
    elif sym.kind == skLabel:
      if sym.offset == -1:
        let labId = ctx.buf.createLabel()
        sym.offset = int(labId)
        ctx.buf.defineLabel(labId)
        ctx.definedLabels.incl int(labId)
      else:
        ctx.buf.defineLabel(LabelId(sym.offset))
        ctx.definedLabels.incl sym.offset
    else:
      error("Symbol is not a label", n)
    inc n

  of MovA64:
    inc n
    let dest = parseDestA64(n, ctx)
    let op = parseOperandA64(n, ctx)
    # Type-check the move against THE shared rule (`movTypeOk`), the same one
    # `genMovX64` applies: a named local carries its declared type, so a narrowing
    # `(mov i8local i64val)` is rejected while a widening one, a sized mem↔reg pair
    # and an ABI-truncating `(arg …)` store are accepted. Both arches must answer
    # identically — arkham emits one program and picks a target afterwards.
    if not movTypeOk(dest.kind, dest.typ, op.kind, op.typ):
      typeError(dest.typ, op.typ, start)
    checkPtrStore(dest.typ, op.kind, op.typ, start)
    if dest.kind == okMem:
      if op.kind == okImm:
        error("Moving immediate to memory not fully supported yet for ARM64", n)
      elif op.kind == okSsize:
        error("Moving ssize to memory not supported", n)
      elif op.kind == okMem:
        error("Cannot move memory to memory", n)
      elif dest.mem.hasIndex:
        let (size, opc) = memWidthOpc(dest.typ, isLoad = false)
        let m = a64IntMemBase(ctx, dest.mem, size)
        if not m.hasIndex:
          arm64.emitLoadStoreUImm(ctx.buf.data, op.reg, m.base, m.offset, size, opc)
        else:
          var base = m.base
          if m.offset != 0:
            emitAddOffsetA64(ctx, arm64.X16, base, m.offset, arm64.X16)
            base = arm64.X16
          arm64.emitLoadStoreReg(ctx.buf.data, op.reg, base, m.index, size, opc, m.shift)
      else:
        let (size, opc) = memWidthOpc(dest.typ, isLoad = false)
        arm64.emitLoadStoreUImm(ctx.buf.data, op.reg, dest.mem.base, dest.mem.offset, size, opc)
    else:
      if op.kind == okSsize:
        arm64.emitMovImm(ctx.buf.data, dest.reg, 0'u16)
        ctx.ssizePatches.add((ctx.buf.data.len - 4, int(op.immVal)))
      elif op.kind == okImm:
        if op.immVal >= 0 and op.immVal <= 0xFFFF:
          arm64.emitMovImm(ctx.buf.data, dest.reg, uint16(op.immVal))
        else:
          # MOVZ + MOVK loads the full 64-bit pattern, including negatives and
          # the raw bit patterns of floating-point constants.
          arm64.emitMovImm64(ctx.buf.data, dest.reg, cast[uint64](op.immVal))
      elif op.kind == okMem and op.mem.hasIndex:
        let (size, opc) = memWidthOpc(op.typ, isLoad = true)
        let m = a64IntMemBase(ctx, op.mem, size)
        if not m.hasIndex:
          arm64.emitLoadStoreUImm(ctx.buf.data, dest.reg, m.base, m.offset, size, opc)
        else:
          var base = m.base
          if m.offset != 0:
            emitAddOffsetA64(ctx, arm64.X16, base, m.offset, arm64.X16)
            base = arm64.X16
          arm64.emitLoadStoreReg(ctx.buf.data, dest.reg, base, m.index, size, opc, m.shift)
      elif op.kind == okMem:
        let (size, opc) = memWidthOpc(op.typ, isLoad = true)
        arm64.emitLoadStoreUImm(ctx.buf.data, dest.reg, op.mem.base, op.mem.offset, size, opc)
      elif dest.reg == op.reg:
        # 64-bit register self-move is a no-op; elide it. This makes a result
        # self-binding such as `(mov (x0) (res ret.0))` cost nothing, so callers
        # can declaratively bind results to their natural register for free.
        discard
      else:
        arm64.emitMov(ctx.buf.data, dest.reg, op.reg)

  of LeaA64:
    # (lea reg <mem>): load the *address* of a stack var / field into `reg`
    # (`add reg, base, #offset`), rather than the value at it.
    inc n
    let dest = parseDestA64(n, ctx)
    let op = parseOperandA64(n, ctx)
    if dest.kind == okMem: error("lea destination must be a register", n)
    if op.kind != okMem: error("lea source must be a memory operand", n)
    if op.mem.hasIndex:
      # `add dest, base, index, lsl #shift` (+ displacement) — an indexed address
      # (e.g. `(at base regIdx)`) folds its index into the computed pointer. A SP base
      # (a stack array) needs the EXTENDED-register ADD (the shifted form reads reg 31
      # as XZR, not SP); a normal base uses the shifted form (which allows shift 0..63).
      if op.mem.base == arm64.SP:
        arm64.emitAddExtended(ctx.buf.data, dest.reg, op.mem.base, op.mem.index, uint8(op.mem.shift))
      else:
        arm64.emitAddShifted(ctx.buf.data, dest.reg, op.mem.base, op.mem.index, uint8(op.mem.shift))
      if op.mem.offset != 0:
        emitAddOffsetA64(ctx, dest.reg, dest.reg, op.mem.offset, arm64.X17)
    else:
      emitAddOffsetA64(ctx, dest.reg, op.mem.base, op.mem.offset, arm64.X17)

  of AdrA64:
    inc n
    let dest = parseDestA64(n, ctx)
    let op = parseOperandA64(n, ctx)
    if dest.kind == okMem: error("ADR destination must be register", n)
    if op.tlvSym != nil:
      # Thread-local variable (macOS/arm64): obtain its address through the TLV
      # descriptor thunk. The descriptor lives in __DATA/__thread_vars; its first
      # word is a function pointer that, called with the descriptor address in
      # x0, returns the variable's address in x0 (preserving all other regs).
      #   adrp x0, desc@PAGE ; add x0, x0, desc@PAGEOFF   (patched in writeMachO)
      #   ldr  x16, [x0]                                   ; load the thunk
      #   blr  x16                                         ; x0 = &var
      #
      # x0 and x16 are the sequence's OWN scratch, not the caller's to lose. Every
      # other instruction here writes its destination and nothing else, and a code
      # generator that staged `f(a, tvar)` — arg 0 already parked in x0 — would
      # otherwise watch that argument vanish with no instruction to blame. Spill
      # both around the thunk so `(adr D tvar)` writes D alone. (`blr` still sets
      # lr, which is why a proc touching a thread-local is analysed as having a
      # call and keeps a frame.)
      arm64.emitSubImm(ctx.buf.data, arm64.SP, arm64.SP, 16'u16)
      arm64.emitStr(ctx.buf.data, arm64.X0, arm64.SP, 0'i32)
      arm64.emitStr(ctx.buf.data, arm64.X16, arm64.SP, 8'i32)
      let pos = ctx.buf.data.getCurrentPosition()
      arm64.emitAdrpAddGvar(ctx.buf.data, arm64.X0)     # x0 = &descriptor
      ctx.tlvSites.add (pos, op.tlvSym)
      arm64.emitLdr(ctx.buf.data, arm64.X16, arm64.X0, 0'i32)
      arm64.emitBlr(ctx.buf.data, arm64.X16)
      # Land the result in `dest` and restore the two scratch registers — skipping
      # whichever one `dest` IS, since that one now holds the address.
      if dest.reg == arm64.X0:
        arm64.emitLdr(ctx.buf.data, arm64.X16, arm64.SP, 8'i32)
      elif dest.reg == arm64.X16:
        arm64.emitMov(ctx.buf.data, arm64.X16, arm64.X0)
        arm64.emitLdr(ctx.buf.data, arm64.X0, arm64.SP, 0'i32)
      else:
        arm64.emitMov(ctx.buf.data, dest.reg, arm64.X0)
        arm64.emitLdr(ctx.buf.data, arm64.X0, arm64.SP, 0'i32)
        arm64.emitLdr(ctx.buf.data, arm64.X16, arm64.SP, 8'i32)
      arm64.emitAddImm(ctx.buf.data, arm64.SP, arm64.SP, 16'u16)
    elif op.gvarSym != nil:
      # Global in __DATA/.bss: form its address with adrp+add (PC-relative adr
      # can't reach __DATA). Emit placeholders; writeMachO patches the page /
      # page-offset once the __DATA layout is known.
      let pos = ctx.buf.data.getCurrentPosition()
      arm64.emitAdrpAddGvar(ctx.buf.data, dest.reg)
      ctx.gvarSites.add (pos, op.gvarSym)
    else:
      # Check if operand is a label: type should be UIntT and not immediate/memory
      if op.typ.kind != UIntT or op.kind == okImm or op.kind == okMem:
        error("ADR source must be a label", n)
      # Long form (`adr`+`add`): a rodata blob can sit anywhere in a multi-megabyte
      # `.text`, well past plain ADR's ±1 MB.
      arm64.emitAdrLong(ctx.buf, dest.reg, op.label)

  of GloadA64, GstoreA64:
    # `(gload D S)` / `(gstore D S)` — scalar load/store of a __DATA/.bss global `S`
    # with the page OFFSET folded into the ldr/str immediate instead of a separate
    # `add`: `adrp x17, S@PAGE ; ldr/str D, [x17, S@PAGEOFF]`. The page-offset patch
    # rides on the SAME gvar site (recorded at the adrp) — writeMachO/writeElf detect
    # the folded ldr/str at pos+4 by its opcode and patch the scaled imm12 there.
    let isLoad = instTag == GloadA64
    inc n
    let dreg = parseDestA64(n, ctx)
    let op = parseOperandA64(n, ctx)
    if dreg.kind != okReg: error((if isLoad: "gload" else: "gstore") & " needs a register", n)
    if op.gvarSym == nil: error((if isLoad: "gload" else: "gstore") & " source must be a global", n)
    # Size the access from the global's own scalar type (byte/half/word/dword).
    let (size, opc) = memWidthOpc(op.gvarSym.typ, isLoad)
    let pos = ctx.buf.data.getCurrentPosition()
    arm64.emitAdrpGvarPage(ctx.buf.data, arm64.X17)          # adrp x17, S@PAGE (page patched)
    ctx.gvarSites.add (pos, op.gvarSym)                      # pos+4 (the ldr/str) gets S@PAGEOFF
    arm64.emitLoadStoreUImm(ctx.buf.data, dreg.reg, arm64.X17, 0'i32, size, opc)

  of AddA64:
    inc n
    let dest = parseDestA64(n, ctx)
    let op = parseOperandA64(n, ctx)
    checkIntegerArithmetic(dest.typ, "add", start)
    checkIntegerArithmetic(op.typ, "add", start)
    checkArithCompatible(dest.typ, op.typ, "add", start)  # sized ints of any width (64-bit reg)
    if dest.kind == okMem:
      error("ADD to memory not supported yet for ARM64", n)
    else:
      if op.kind == okSsize:
        # A PAIR: `add sp, sp, #lo12` + `add sp, sp, #hi12, lsl #12`. The frame size is
        # only known at patch time and ADD's immediate is 12 bits, so a single
        # instruction silently truncated any frame over 4095 bytes (a 10KB frame came
        # out as `sub sp, sp, #2000`, leaving every local access off the end of the
        # stack — an ASLR-dependent crash). The patcher fills each half; see `finalize`.
        arm64.emitAddImm(ctx.buf.data, dest.reg, dest.reg, 0'u16)
        ctx.ssizePatches.add((ctx.buf.data.len - 4, int(op.immVal)))
        arm64.emitAddImmShifted12(ctx.buf.data, dest.reg, dest.reg, 0'u16)
        ctx.ssizePatches.add((ctx.buf.data.len - 4, int(op.immVal)))
      elif op.kind == okImm or op.kind == okCsize:
        if op.immVal >= 0 and op.immVal <= 4095:
          arm64.emitAddImm(ctx.buf.data, dest.reg, dest.reg, uint16(op.immVal))
        else:
          # ADD's immediate field is 12 bits; a larger (or negative) constant is
          # synthesized through the reserved assembler scratch X17. (The former
          # `<= 0xFFFF` gate silently mis-encoded 4096..65535: the immediate
          # overflowed into the shift/opcode bits.)
          arm64.emitMovImm64(ctx.buf.data, arm64.X17, cast[uint64](op.immVal))
          arm64.emitAdd(ctx.buf.data, dest.reg, dest.reg, arm64.X17)
      elif op.kind == okMem:
        error("ADD from memory not supported yet", n)
      else:
        arm64.emitAdd(ctx.buf.data, dest.reg, dest.reg, op.reg)

  of SubA64:
    inc n
    let dest = parseDestA64(n, ctx)
    let op = parseOperandA64(n, ctx)
    checkIntegerArithmetic(dest.typ, "sub", start)
    checkIntegerArithmetic(op.typ, "sub", start)
    checkArithCompatible(dest.typ, op.typ, "sub", start)  # sized ints of any width (64-bit reg)
    if dest.kind == okMem:
      error("SUB to memory not supported yet for ARM64", n)
    else:
      if op.kind == okSsize:
        arm64.emitSubImm(ctx.buf.data, dest.reg, dest.reg, 0'u16)   # lo12 (see AddA64)
        ctx.ssizePatches.add((ctx.buf.data.len - 4, int(op.immVal)))
        arm64.emitSubImmShifted12(ctx.buf.data, dest.reg, dest.reg, 0'u16)  # hi12
        ctx.ssizePatches.add((ctx.buf.data.len - 4, int(op.immVal)))
        if ctx.inPrologue and dest.reg == arm64.SP:
          # Both halves of the pair are one CFA event; record it after the second
          # so the FDE's `advance_loc` covers them together.
          ctx.cfiStep(0, [], ssizeSlot = true)        # delta filled in at proc end
      elif op.kind == okImm or op.kind == okCsize:
        if op.immVal >= 0 and op.immVal <= 4095:
          arm64.emitSubImm(ctx.buf.data, dest.reg, dest.reg, uint16(op.immVal))
        else:
          # SUB's immediate field is 12 bits — synthesize larger/negative constants
          # through X17 (see the ADD case above for the mis-encode this closes).
          arm64.emitMovImm64(ctx.buf.data, arm64.X17, cast[uint64](op.immVal))
          arm64.emitSub(ctx.buf.data, dest.reg, dest.reg, arm64.X17)
      elif op.kind == okMem:
        error("SUB from memory not supported yet", n)
      else:
        arm64.emitSub(ctx.buf.data, dest.reg, dest.reg, op.reg)

  of MulA64:
    inc n
    let dest = parseDestA64(n, ctx)
    let op = parseOperandA64(n, ctx)
    checkIntegerType(dest.typ, "mul", start)
    checkIntegerType(op.typ, "mul", start)
    if dest.kind == okMem: error("MUL destination cannot be memory", n)
    if op.kind == okImm: error("MUL immediate not supported", n)
    if op.kind == okMem: error("MUL memory not supported yet", n)
    arm64.emitMul(ctx.buf.data, dest.reg, dest.reg, op.reg)

  of SmulhA64, UmulhA64:
    inc n
    let dest = parseDestA64(n, ctx)
    let op = parseOperandA64(n, ctx)
    let mn = if instTag == SmulhA64: "smulh" else: "umulh"
    checkIntegerType(dest.typ, mn, start)
    checkIntegerType(op.typ, mn, start)
    if dest.kind == okMem: error(mn & " destination cannot be memory", n)
    if op.kind == okImm: error(mn & " immediate not supported", n)
    if op.kind == okMem: error(mn & " memory not supported yet", n)
    if instTag == SmulhA64:
      arm64.emitSmulh(ctx.buf.data, dest.reg, dest.reg, op.reg)
    else:
      arm64.emitUmulh(ctx.buf.data, dest.reg, dest.reg, op.reg)

  of SdivA64:
    inc n
    let dest = parseDestA64(n, ctx)
    let op = parseOperandA64(n, ctx)
    checkIntegerType(dest.typ, "sdiv", start)
    checkIntegerType(op.typ, "sdiv", start)
    if dest.kind == okMem: error("SDIV destination cannot be memory", n)
    if op.kind == okImm: error("SDIV immediate not supported", n)
    if op.kind == okMem: error("SDIV memory not supported yet", n)
    arm64.emitSdiv(ctx.buf.data, dest.reg, dest.reg, op.reg)

  of UdivA64:
    inc n
    let dest = parseDestA64(n, ctx)
    let op = parseOperandA64(n, ctx)
    checkIntegerType(dest.typ, "udiv", start)
    checkIntegerType(op.typ, "udiv", start)
    if dest.kind == okMem: error("UDIV destination cannot be memory", n)
    if op.kind == okImm: error("UDIV immediate not supported", n)
    if op.kind == okMem: error("UDIV memory not supported yet", n)
    arm64.emitUdiv(ctx.buf.data, dest.reg, dest.reg, op.reg)

  of AndA64:
    inc n
    let dest = parseDestA64(n, ctx)
    let op = parseOperandA64(n, ctx)
    checkBitwiseType(dest.typ, "and", start)
    checkBitwiseType(op.typ, "and", start)
    checkBitwiseCompatible(dest.typ, op.typ, "and", start)
    if dest.kind == okMem: error("AND to memory not supported yet", n)
    else:
      if op.kind == okImm:
        # AArch64 takes the mask directly when it is a "bitmask immediate" — which
        # every bitfield mask is. Otherwise it has to reach a register; X17 is the
        # assembler's own scratch (never allocated by arkham), same as `add3` above.
        if arm64.isLogicalImm(cast[uint64](op.immVal)):
          arm64.emitAndImm(ctx.buf.data, dest.reg, dest.reg, cast[uint64](op.immVal))
        else:
          arm64.emitMovImm64(ctx.buf.data, arm64.X17, cast[uint64](op.immVal))
          arm64.emitAnd(ctx.buf.data, dest.reg, dest.reg, arm64.X17)
      elif op.kind == okMem: error("AND from memory not supported yet", n)
      else:
        arm64.emitAnd(ctx.buf.data, dest.reg, dest.reg, op.reg)

  of OrrA64:
    inc n
    let dest = parseDestA64(n, ctx)
    let op = parseOperandA64(n, ctx)
    checkBitwiseType(dest.typ, "orr", start)
    checkBitwiseType(op.typ, "orr", start)
    checkBitwiseCompatible(dest.typ, op.typ, "orr", start)
    if dest.kind == okMem: error("ORR to memory not supported yet", n)
    else:
      if op.kind == okImm:
        # AArch64 takes the mask directly when it is a "bitmask immediate" — which
        # every bitfield mask is. Otherwise it has to reach a register; X17 is the
        # assembler's own scratch (never allocated by arkham), same as `add3` above.
        if arm64.isLogicalImm(cast[uint64](op.immVal)):
          arm64.emitOrrImm(ctx.buf.data, dest.reg, dest.reg, cast[uint64](op.immVal))
        else:
          arm64.emitMovImm64(ctx.buf.data, arm64.X17, cast[uint64](op.immVal))
          arm64.emitOrr(ctx.buf.data, dest.reg, dest.reg, arm64.X17)
      elif op.kind == okMem: error("ORR from memory not supported yet", n)
      else:
        arm64.emitOrr(ctx.buf.data, dest.reg, dest.reg, op.reg)

  of EorA64:
    inc n
    let dest = parseDestA64(n, ctx)
    let op = parseOperandA64(n, ctx)
    checkBitwiseType(dest.typ, "eor", start)
    checkBitwiseType(op.typ, "eor", start)
    checkBitwiseCompatible(dest.typ, op.typ, "eor", start)
    if dest.kind == okMem: error("EOR to memory not supported yet", n)
    else:
      if op.kind == okImm:
        # AArch64 takes the mask directly when it is a "bitmask immediate" — which
        # every bitfield mask is. Otherwise it has to reach a register; X17 is the
        # assembler's own scratch (never allocated by arkham), same as `add3` above.
        if arm64.isLogicalImm(cast[uint64](op.immVal)):
          arm64.emitEorImm(ctx.buf.data, dest.reg, dest.reg, cast[uint64](op.immVal))
        else:
          arm64.emitMovImm64(ctx.buf.data, arm64.X17, cast[uint64](op.immVal))
          arm64.emitEor(ctx.buf.data, dest.reg, dest.reg, arm64.X17)
      elif op.kind == okMem: error("EOR from memory not supported yet", n)
      else:
        arm64.emitEor(ctx.buf.data, dest.reg, dest.reg, op.reg)

  of LslA64:
    inc n
    let dest = parseDestA64(n, ctx)
    let op = parseOperandA64(n, ctx)
    checkBitwiseType(dest.typ, "lsl", start)
    if dest.kind == okMem: error("Shift destination cannot be memory", n)
    if op.kind == okImm:
      if op.immVal >= 0 and op.immVal <= 63:
        arm64.emitLslImm(ctx.buf.data, dest.reg, dest.reg, uint8(op.immVal))
      else:
        error("Shift amount must be 0-63", n)
    else:
      arm64.emitLsl(ctx.buf.data, dest.reg, dest.reg, op.reg)

  of LsrA64:
    inc n
    let dest = parseDestA64(n, ctx)
    let op = parseOperandA64(n, ctx)
    checkBitwiseType(dest.typ, "lsr", start)
    if dest.kind == okMem: error("Shift destination cannot be memory", n)
    if op.kind == okImm:
      if op.immVal >= 0 and op.immVal <= 63:
        arm64.emitLsrImm(ctx.buf.data, dest.reg, dest.reg, uint8(op.immVal))
      else:
        error("Shift amount must be 0-63", n)
    else:
      arm64.emitLsr(ctx.buf.data, dest.reg, dest.reg, op.reg)

  of AsrA64:
    inc n
    let dest = parseDestA64(n, ctx)
    let op = parseOperandA64(n, ctx)
    checkBitwiseType(dest.typ, "asr", start)
    if dest.kind == okMem: error("Shift destination cannot be memory", n)
    if op.kind == okImm:
      if op.immVal >= 0 and op.immVal <= 63:
        arm64.emitAsrImm(ctx.buf.data, dest.reg, dest.reg, uint8(op.immVal))
      else:
        error("Shift amount must be 0-63", n)
    else:
      arm64.emitAsr(ctx.buf.data, dest.reg, dest.reg, op.reg)

  of Add3A64:
    inc n
    let (rd, rn, rm, dstT) = parse3OperandsA64(n, ctx, "add3")
    checkIntegerArithmetic(dstT, "add", start)
    checkIntegerArithmetic(rm.typ, "add", start)
    if rm.kind == okImm or rm.kind == okCsize:
      if rm.immVal >= 0 and rm.immVal <= 4095:
        arm64.emitAddImm(ctx.buf.data, rd, rn, uint16(rm.immVal))
      else:
        arm64.emitMovImm64(ctx.buf.data, arm64.X17, cast[uint64](rm.immVal))
        arm64.emitAdd(ctx.buf.data, rd, rn, arm64.X17)
    elif rm.kind == okMem: error("add3 from memory not supported", n)
    else: arm64.emitAdd(ctx.buf.data, rd, rn, rm.reg)

  of Sub3A64:
    inc n
    let (rd, rn, rm, dstT) = parse3OperandsA64(n, ctx, "sub3")
    checkIntegerArithmetic(dstT, "sub", start)
    checkIntegerArithmetic(rm.typ, "sub", start)
    if rm.kind == okImm or rm.kind == okCsize:
      if rm.immVal >= 0 and rm.immVal <= 4095:
        arm64.emitSubImm(ctx.buf.data, rd, rn, uint16(rm.immVal))
      else:
        arm64.emitMovImm64(ctx.buf.data, arm64.X17, cast[uint64](rm.immVal))
        arm64.emitSub(ctx.buf.data, rd, rn, arm64.X17)
    elif rm.kind == okMem: error("sub3 from memory not supported", n)
    else: arm64.emitSub(ctx.buf.data, rd, rn, rm.reg)

  of Mul3A64:
    inc n
    let (rd, rn, rm, dstT) = parse3OperandsA64(n, ctx, "mul3")
    checkIntegerType(dstT, "mul", start)
    checkIntegerType(rm.typ, "mul", start)
    if rm.kind != okReg: error("mul3 second source must be a register", n)
    arm64.emitMul(ctx.buf.data, rd, rn, rm.reg)

  of And3A64:
    inc n
    let (rd, rn, rm, dstT) = parse3OperandsA64(n, ctx, "and3")
    checkBitwiseType(dstT, "and", start)
    checkBitwiseType(rm.typ, "and", start)
    if rm.kind == okImm:
      if arm64.isLogicalImm(cast[uint64](rm.immVal)):
        arm64.emitAndImm(ctx.buf.data, rd, rn, cast[uint64](rm.immVal))
      else:
        arm64.emitMovImm64(ctx.buf.data, arm64.X17, cast[uint64](rm.immVal))
        arm64.emitAnd(ctx.buf.data, rd, rn, arm64.X17)
    elif rm.kind != okReg: error("and3 second source must be a register or immediate", n)
    else: arm64.emitAnd(ctx.buf.data, rd, rn, rm.reg)

  of Orr3A64:
    inc n
    let (rd, rn, rm, dstT) = parse3OperandsA64(n, ctx, "orr3")
    checkBitwiseType(dstT, "orr", start)
    checkBitwiseType(rm.typ, "orr", start)
    if rm.kind == okImm:
      if arm64.isLogicalImm(cast[uint64](rm.immVal)):
        arm64.emitOrrImm(ctx.buf.data, rd, rn, cast[uint64](rm.immVal))
      else:
        arm64.emitMovImm64(ctx.buf.data, arm64.X17, cast[uint64](rm.immVal))
        arm64.emitOrr(ctx.buf.data, rd, rn, arm64.X17)
    elif rm.kind != okReg: error("orr3 second source must be a register or immediate", n)
    else: arm64.emitOrr(ctx.buf.data, rd, rn, rm.reg)

  of Eor3A64:
    inc n
    let (rd, rn, rm, dstT) = parse3OperandsA64(n, ctx, "eor3")
    checkBitwiseType(dstT, "eor", start)
    checkBitwiseType(rm.typ, "eor", start)
    if rm.kind == okImm:
      if arm64.isLogicalImm(cast[uint64](rm.immVal)):
        arm64.emitEorImm(ctx.buf.data, rd, rn, cast[uint64](rm.immVal))
      else:
        arm64.emitMovImm64(ctx.buf.data, arm64.X17, cast[uint64](rm.immVal))
        arm64.emitEor(ctx.buf.data, rd, rn, arm64.X17)
    elif rm.kind != okReg: error("eor3 second source must be a register or immediate", n)
    else: arm64.emitEor(ctx.buf.data, rd, rn, rm.reg)

  of Lsl3A64:
    inc n
    let (rd, rn, rm, dstT) = parse3OperandsA64(n, ctx, "lsl3")
    checkBitwiseType(dstT, "lsl", start)
    if rm.kind == okImm:
      if rm.immVal >= 0 and rm.immVal <= 63:
        arm64.emitLslImm(ctx.buf.data, rd, rn, uint8(rm.immVal))
      else: error("Shift amount must be 0-63", n)
    else: arm64.emitLsl(ctx.buf.data, rd, rn, rm.reg)

  of Lsr3A64:
    inc n
    let (rd, rn, rm, dstT) = parse3OperandsA64(n, ctx, "lsr3")
    checkBitwiseType(dstT, "lsr", start)
    if rm.kind == okImm:
      if rm.immVal >= 0 and rm.immVal <= 63:
        arm64.emitLsrImm(ctx.buf.data, rd, rn, uint8(rm.immVal))
      else: error("Shift amount must be 0-63", n)
    else: arm64.emitLsr(ctx.buf.data, rd, rn, rm.reg)

  of Asr3A64:
    inc n
    let (rd, rn, rm, dstT) = parse3OperandsA64(n, ctx, "asr3")
    checkBitwiseType(dstT, "asr", start)
    if rm.kind == okImm:
      if rm.immVal >= 0 and rm.immVal <= 63:
        arm64.emitAsrImm(ctx.buf.data, rd, rn, uint8(rm.immVal))
      else: error("Shift amount must be 0-63", n)
    else: arm64.emitAsr(ctx.buf.data, rd, rn, rm.reg)

  of AddwA64:
    inc n
    let dest = parseDestA64(n, ctx)
    let op = parseOperandA64(n, ctx)
    checkIntegerArithmetic(dest.typ, "addw", start)
    checkIntegerArithmetic(op.typ, "addw", start)
    if dest.kind == okMem: error("ADDW to memory not supported", n)
    elif op.kind == okImm or op.kind == okCsize:
      if op.immVal >= 0 and op.immVal <= 4095:
        arm64.emitAddImm(ctx.buf.data, dest.reg, dest.reg, uint16(op.immVal), w = true)
      else:
        arm64.emitMovImm64(ctx.buf.data, arm64.X17, cast[uint64](op.immVal))
        arm64.emitAdd(ctx.buf.data, dest.reg, dest.reg, arm64.X17, w = true)
    elif op.kind == okMem: error("ADDW from memory not supported", n)
    else: arm64.emitAdd(ctx.buf.data, dest.reg, dest.reg, op.reg, w = true)

  of SubwA64:
    inc n
    let dest = parseDestA64(n, ctx)
    let op = parseOperandA64(n, ctx)
    checkIntegerArithmetic(dest.typ, "subw", start)
    checkIntegerArithmetic(op.typ, "subw", start)
    if dest.kind == okMem: error("SUBW to memory not supported", n)
    elif op.kind == okImm or op.kind == okCsize:
      if op.immVal >= 0 and op.immVal <= 4095:
        arm64.emitSubImm(ctx.buf.data, dest.reg, dest.reg, uint16(op.immVal), w = true)
      else:
        arm64.emitMovImm64(ctx.buf.data, arm64.X17, cast[uint64](op.immVal))
        arm64.emitSub(ctx.buf.data, dest.reg, dest.reg, arm64.X17, w = true)
    elif op.kind == okMem: error("SUBW from memory not supported", n)
    else: arm64.emitSub(ctx.buf.data, dest.reg, dest.reg, op.reg, w = true)

  of MulwA64:
    inc n
    let dest = parseDestA64(n, ctx)
    let op = parseOperandA64(n, ctx)
    checkIntegerType(dest.typ, "mulw", start)
    checkIntegerType(op.typ, "mulw", start)
    if dest.kind == okMem: error("MULW destination cannot be memory", n)
    if op.kind == okImm: error("MULW immediate not supported", n)
    if op.kind == okMem: error("MULW memory not supported", n)
    arm64.emitMul(ctx.buf.data, dest.reg, dest.reg, op.reg, w = true)

  of Addw3A64:
    inc n
    let (rd, rn, rm, dstT) = parse3OperandsA64(n, ctx, "addw3")
    checkIntegerArithmetic(dstT, "addw", start)
    checkIntegerArithmetic(rm.typ, "addw", start)
    if rm.kind == okImm or rm.kind == okCsize:
      if rm.immVal >= 0 and rm.immVal <= 4095:
        arm64.emitAddImm(ctx.buf.data, rd, rn, uint16(rm.immVal), w = true)
      else:
        arm64.emitMovImm64(ctx.buf.data, arm64.X17, cast[uint64](rm.immVal))
        arm64.emitAdd(ctx.buf.data, rd, rn, arm64.X17, w = true)
    elif rm.kind == okMem: error("addw3 from memory not supported", n)
    else: arm64.emitAdd(ctx.buf.data, rd, rn, rm.reg, w = true)

  of Subw3A64:
    inc n
    let (rd, rn, rm, dstT) = parse3OperandsA64(n, ctx, "subw3")
    checkIntegerArithmetic(dstT, "subw", start)
    checkIntegerArithmetic(rm.typ, "subw", start)
    if rm.kind == okImm or rm.kind == okCsize:
      if rm.immVal >= 0 and rm.immVal <= 4095:
        arm64.emitSubImm(ctx.buf.data, rd, rn, uint16(rm.immVal), w = true)
      else:
        arm64.emitMovImm64(ctx.buf.data, arm64.X17, cast[uint64](rm.immVal))
        arm64.emitSub(ctx.buf.data, rd, rn, arm64.X17, w = true)
    elif rm.kind == okMem: error("subw3 from memory not supported", n)
    else: arm64.emitSub(ctx.buf.data, rd, rn, rm.reg, w = true)

  of Mulw3A64:
    inc n
    let (rd, rn, rm, dstT) = parse3OperandsA64(n, ctx, "mulw3")
    checkIntegerType(dstT, "mulw", start)
    checkIntegerType(rm.typ, "mulw", start)
    if rm.kind != okReg: error("mulw3 second source must be a register", n)
    arm64.emitMul(ctx.buf.data, rd, rn, rm.reg, w = true)

  of NegA64:
    inc n
    let op = parseDestA64(n, ctx)
    checkIntegerArithmetic(op.typ, "neg", start)
    if op.kind == okMem: error("NEG memory not supported yet", n)
    arm64.emitNeg(ctx.buf.data, op.reg, op.reg)

  # Bit-counting / bit- and byte-reversal: `(clz D S N)`, `(rbit D S N)`,
  # `(rev D S N)`. All are three-address (D is a pure destination), so unlike
  # x86's `bswap` they need no copy into the destination first. `N` (32 or 64) is
  # the operand size, given EXPLICITLY: a 32-bit `clz` counts from bit 31, and the
  # declared type of a bit-count destination says nothing about that width.
  of ClzA64, RbitA64, RevA64:
    let mnemonic = $instTag
    inc n
    let dest = parseDestA64(n, ctx)
    let op = parseOperandA64(n, ctx)
    checkBitwiseType(dest.typ, mnemonic, start)
    checkBitwiseType(op.typ, mnemonic, start)
    if dest.kind != okReg: error(mnemonic & " destination must be a register", n)
    if op.kind != okReg: error(mnemonic & " source must be a register", n)
    if n.kind != IntLit: error(mnemonic & " requires a width operand (32 or 64)", n)
    let bits = int(getInt(n)); inc n
    if bits != 32 and bits != 64: error(mnemonic & " width must be 32 or 64", n)
    let w = bits == 32
    case instTag
    of ClzA64:  arm64.emitClz(ctx.buf.data, dest.reg, op.reg, w)
    of RbitA64: arm64.emitRbit(ctx.buf.data, dest.reg, op.reg, w)
    else:       arm64.emitRev(ctx.buf.data, dest.reg, op.reg, w)

  of CmpA64:
    inc n
    let dest = parseDestA64(n, ctx)
    let op = parseOperandA64(n, ctx)
    # Comparisons work on integers, pointers, bool (the "if bool" test) and `nil` —
    # the same loose rule as x64's CmpX64 (was the stricter integer-arithmetic check).
    checkComparable(dest.typ, "cmp", start)
    checkComparable(op.typ, "cmp", start)
    checkCmpCompatible(dest.typ, op.typ, start)
    if dest.kind == okMem:
      error("CMP memory not supported yet", n)
    else:
      if op.kind == okImm:
        if op.immVal >= 0 and op.immVal <= 4095:
          arm64.emitCmpImm(ctx.buf.data, dest.reg, uint16(op.immVal))
        else:
          # CMP's immediate field is 12 bits — synthesize larger/negative constants
          # through the reserved scratch X17. (The former `<= 0xFFFF` gate silently
          # MIS-ENCODED 4096..65535: the immediate overflowed into the opcode bits.)
          arm64.emitMovImm64(ctx.buf.data, arm64.X17, cast[uint64](op.immVal))
          arm64.emitCmp(ctx.buf.data, dest.reg, arm64.X17)
      elif op.kind == okMem:
        error("CMP memory not supported yet", n)
      else:
        arm64.emitCmp(ctx.buf.data, dest.reg, op.reg)

  of CseleqA64, CselneA64, CselltA64, CselleA64, CselgtA64, CselgeA64,
     CselloA64, CsellsA64, CselhiA64, CselhsA64:
    # (csel<cc> D S1 S2): D = S1 if <cc> else S2, reading the NZCV flags of the
    # preceding `cmp` — the flag-consuming select that turns a min/max/abs branch
    # diamond into straight-line code. Register-only: CSEL has no immediate or
    # memory form, so constants must be materialized into a register first.
    inc n
    let dest = parseDestA64(n, ctx)
    let s1 = parseOperandA64(n, ctx)
    let s2 = parseOperandA64(n, ctx)
    if dest.kind != okReg: error("CSEL destination must be a register", n)
    for src in [s1, s2]:
      if src.kind != okReg: error("CSEL sources must be registers", n)
      # Both sources must fit the destination's type: the `mov` rule, applied twice.
      if dest.typ != nil and src.typ != nil and not movCompatible(dest.typ, src.typ):
        typeError(dest.typ, src.typ, start)
    arm64.emitCsel(ctx.buf.data, dest.reg, s1.reg, s2.reg, a64CondOf(instTag))

  of CseteqA64, CsetneA64, CsetltA64, CsetleA64, CsetgtA64, CsetgeA64,
     CsetloA64, CsetlsA64, CsethiA64, CsethsA64:
    # (cset<cc> D): D = 1 if <cc> else 0 — materializes the NZCV flags of the
    # preceding `cmp` as a bool value (alias of CSINC D, XZR, XZR, inv(<cc>)).
    inc n
    let dest = parseDestA64(n, ctx)
    if dest.kind != okReg: error("CSET destination must be a register", n)
    if dest.typ != nil and dest.typ.kind notin {IntT, UIntT, BoolT, IntLitT}:
      error("CSET requires an integer or bool destination", n)
    arm64.emitCset(ctx.buf.data, dest.reg, a64CondOf(instTag))

  of RetA64:
    inc n
    arm64.emitRet(ctx.buf.data)

  of NopA64:
    inc n
    arm64.emitNop(ctx.buf.data)

  of SvcA64:
    if ctx.inCall and ctx.callContext.isSyscall:
      # Consumes the whole node (`intoOperands`), so it wants the head back
      # rather than the escaped-id step-over `genInstA64` already did.
      n = start
      genSyscallMarkerA64(n, ctx)   # `(svc)` as the prepare invocation marker
    else:
      inc n
      let op = parseOperandA64(n, ctx)
      if op.kind != okImm:
        error("SVC requires immediate operand", n)
      if op.immVal < 0 or op.immVal > 0xFFFF:
        error("SVC immediate must be 0-65535", n)
      arm64.emitSvc(ctx.buf.data, uint16(op.immVal))  # a raw `svc` (e.g. entry exit)

  of LdrA64:
    inc n
    let dest = parseDestA64(n, ctx)
    let op = parseOperandA64(n, ctx)
    if dest.kind == okMem: error("LDR destination must be register", n)
    if op.kind == okMem:
      ctx.buf.data.emitLdr(dest.reg, op.mem.base, op.mem.offset)
    else:
      error("LDR source must be memory", n)

  of StrA64:
    inc n
    let dest = parseDestA64(n, ctx)
    let op = parseOperandA64(n, ctx)
    if dest.kind != okMem: error("STR destination must be memory", n)
    if op.kind == okMem: error("STR source cannot be memory", n)
    ctx.buf.data.emitStr(op.reg, dest.mem.base, dest.mem.offset)

  of LdaxrA64:
    # (ldaxr Dt Sptr bits?) — Dt ← exclusive-acquire load of [Sptr]. Operands may be
    # `rebind`-bound scratch names (the atomics lowering binds its temps). The optional
    # trailing int is the access width in bits (default 64); arkham emits it so a
    # sub-64-bit atomic uses the matching `ldaxr{b,h}`/`Wt` form (see sizeFieldA64).
    inc n
    let rt = parseGprA64(n, ctx)
    let rn = parseGprA64(n, ctx)
    let bits = if n.kind == IntLit: (let b = int(n.intVal); inc n; b) else: 64
    arm64.emitLdaxr(ctx.buf.data, rt, rn, bits)

  of StlxrA64:
    # (stlxr St Dval Sptr bits?) — store-release-exclusive Dval to [Sptr]; St ← status.
    inc n
    let rs = parseGprA64(n, ctx)
    let rt = parseGprA64(n, ctx)
    let rn = parseGprA64(n, ctx)
    let bits = if n.kind == IntLit: (let b = int(n.intVal); inc n; b) else: 64
    arm64.emitStlxr(ctx.buf.data, rs, rt, rn, bits)

  of LdarA64:
    # (ldar Dt Sptr bits?) — Dt ← acquire load of [Sptr].
    inc n
    let rt = parseGprA64(n, ctx)
    let rn = parseGprA64(n, ctx)
    let bits = if n.kind == IntLit: (let b = int(n.intVal); inc n; b) else: 64
    arm64.emitLdar(ctx.buf.data, rt, rn, bits)

  of StlrA64:
    # (stlr Dval Sptr bits?) — release store Dval to [Sptr].
    inc n
    let rt = parseGprA64(n, ctx)
    let rn = parseGprA64(n, ctx)
    let bits = if n.kind == IntLit: (let b = int(n.intVal); inc n; b) else: 64
    arm64.emitStlr(ctx.buf.data, rt, rn, bits)

  of LdrbA64:
    # (ldrb Dt Bbase Iindex) — Dt ← zero-extended byte [Bbase + Iindex].
    inc n
    let rt = parseGprA64(n, ctx)
    let rn = parseGprA64(n, ctx)
    let rm = parseGprA64(n, ctx)
    arm64.emitLdrbReg(ctx.buf.data, rt, rn, rm)

  of StrbA64:
    # (strb Dval Bbase Iindex) — store low byte of Dval to [Bbase + Iindex].
    inc n
    let rt = parseGprA64(n, ctx)
    let rn = parseGprA64(n, ctx)
    let rm = parseGprA64(n, ctx)
    arm64.emitStrbReg(ctx.buf.data, rt, rn, rm)

  of DmbA64:
    inc n
    arm64.emitDmbIsh(ctx.buf.data)

  of ClrexA64:
    inc n
    arm64.emitClrex(ctx.buf.data)

  of VgreqA64:
    # (vgreq D S) — D = valgrind's answer to the request block at S.
    #
    # Nothing here is checked against valgrind's protocol because nothing here can
    # get it wrong: the register assignment is fixed inside the encoder, not read
    # off these operands. What IS checked is the only thing the caller chooses — two
    # registers of a plausible type — since the encoder writes through both.
    inc n
    let dest = parseDestA64(n, ctx)
    let op = parseOperandA64(n, ctx)
    checkExchangeType(dest.typ, "vgreq", start)
    checkExchangeType(op.typ, "vgreq", start)
    if dest.kind != okReg: error("vgreq destination must be a register", n)
    if op.kind != okReg: error("vgreq request-block operand must be a register", n)
    arm64.emitVgClientRequest(ctx.buf.data, dest.reg, op.reg)

  of FmovA64:
    # (fmov D S): D=fp,S=fp → reg copy; D=fp,S=gpr / D=gpr,S=fp → bit move.
    # The size (s/d) comes from whichever operand is an fp register.
    inc n
    if isA64FpOperand(n, ctx):
      let single = isA64FpSingle(n, ctx)
      let rd = parseFloatOperandA64(n, ctx)
      if isA64FpOperand(n, ctx):
        arm64.emitFmov(ctx.buf.data, rd, parseFloatOperandA64(n, ctx), single)
      else:
        arm64.emitFmovFromGpr(ctx.buf.data, rd, parseRegisterA64(n), single)
    else:
      let rd = parseRegisterA64(n)
      let single = isA64FpSingle(n, ctx)
      arm64.emitFmovToGpr(ctx.buf.data, rd, parseFloatOperandA64(n, ctx), single)

  of FaddA64, FsubA64, FmulA64, FdivA64:
    # (fop D S) → D = D op S  (emitted as `fop Dd, Dd, Ds`).
    inc n
    let single = isA64FpSingle(n, ctx)
    let rd = parseFloatOperandA64(n, ctx)
    let rs = parseFloatOperandA64(n, ctx)
    case instTag
    of FaddA64: arm64.emitFadd(ctx.buf.data, rd, rd, rs, single)
    of FsubA64: arm64.emitFsub(ctx.buf.data, rd, rd, rs, single)
    of FmulA64: arm64.emitFmul(ctx.buf.data, rd, rd, rs, single)
    else:       arm64.emitFdiv(ctx.buf.data, rd, rd, rs, single)

  of FnegA64:
    inc n
    let single = isA64FpSingle(n, ctx)
    let rd = parseFloatOperandA64(n, ctx)
    arm64.emitFneg(ctx.buf.data, rd, rd, single)

  of FcmpA64:
    inc n
    let single = isA64FpSingle(n, ctx)
    let rn = parseFloatOperandA64(n, ctx)
    let rm = parseFloatOperandA64(n, ctx)
    arm64.emitFcmp(ctx.buf.data, rn, rm, single)

  of FldrA64:
    # (fldr D <mem>) — load a double/single.
    inc n
    let single = isA64FpSingle(n, ctx)
    let rt = parseFloatOperandA64(n, ctx)
    let op = parseOperandA64(n, ctx)
    if op.kind != okMem: error("FLDR source must be memory", n)
    let (base, off) = a64FpMemBase(ctx, op.mem, single)
    arm64.emitFldr(ctx.buf.data, rt, base, off, single)

  of FstrA64:
    # (fstr <mem> D) — store a double/single.
    inc n
    let dest = parseOperandA64(n, ctx)
    if dest.kind != okMem: error("FSTR destination must be memory", n)
    let single = isA64FpSingle(n, ctx)
    let rt = parseFloatOperandA64(n, ctx)
    let (base, off) = a64FpMemBase(ctx, dest.mem, single)
    arm64.emitFstr(ctx.buf.data, rt, base, off, single)

  of ScvtfA64, UcvtfA64:
    # (scvtf Dfp Sgpr) — int → double/single.
    inc n
    let single = isA64FpSingle(n, ctx)
    let rd = parseFloatOperandA64(n, ctx)
    let rn = parseRegisterA64(n)
    if instTag == ScvtfA64: arm64.emitScvtf(ctx.buf.data, rd, rn, single)
    else:                   arm64.emitUcvtf(ctx.buf.data, rd, rn, single)

  of FcvtzsA64, FcvtzuA64:
    # (fcvtzs Dgpr Sfp) — double/single → int (toward zero).
    inc n
    let rd = parseRegisterA64(n)
    let single = isA64FpSingle(n, ctx)
    let rn = parseFloatOperandA64(n, ctx)
    if instTag == FcvtzsA64: arm64.emitFcvtzs(ctx.buf.data, rd, rn, single)
    else:                    arm64.emitFcvtzu(ctx.buf.data, rd, rn, single)

  of FcvtA64:
    # (fcvt Ddst Ssrc) — precision convert; direction from the operand sizes.
    inc n
    let dstSingle = isA64FpSingle(n, ctx)
    let rd = parseFloatOperandA64(n, ctx)
    let rn = parseFloatOperandA64(n, ctx)
    if dstSingle: arm64.emitFcvtToSingle(ctx.buf.data, rd, rn)  # double → single
    else:         arm64.emitFcvtToDouble(ctx.buf.data, rd, rn)  # single → double

  of FldrqA64:
    # (fldrq D <mem>) — 128-bit q load; D names the v register by its d/s tag.
    inc n
    let rt = parseFloatOperandA64(n, ctx)
    let op = parseOperandA64(n, ctx)
    if op.kind != okMem: error("FLDRQ source must be memory", n)
    arm64.emitLdrQ(ctx.buf.data, rt, op.mem.base, op.mem.offset)

  of FstrqA64:
    # (fstrq <mem> D) — 128-bit q store, operand order as `fstr`.
    inc n
    let dest = parseOperandA64(n, ctx)
    if dest.kind != okMem: error("FSTRQ destination must be memory", n)
    let rt = parseFloatOperandA64(n, ctx)
    arm64.emitStrQ(ctx.buf.data, rt, dest.mem.base, dest.mem.offset)

  of VfaddA64, VfsubA64, VfmulA64, VfmlaA64:
    # (vop D A B bits?) — lane-wise vector fp; `.2d` when d-spelled, `.4s` when
    # s-spelled. The optional trailing lane-bits literal (32/64) overrides the
    # spelling-derived arrangement: a 128-bit VALUE binding (`(f 128)`, arkham's
    # vector locals) names the register without naming a lane width, so the
    # instruction carries it explicitly — the same shape as `(clz D S N)`.
    inc n
    var single = isA64FpSingle(n, ctx)
    let rd = parseFloatOperandA64(n, ctx)
    let ra = parseFloatOperandA64(n, ctx)
    let rb = parseFloatOperandA64(n, ctx)
    if n.kind == IntLit:
      single = int(n.intVal) == 32
      inc n
    case instTag
    of VfaddA64: arm64.emitVFadd(ctx.buf.data, rd, ra, rb, single)
    of VfsubA64: arm64.emitVFsub(ctx.buf.data, rd, ra, rb, single)
    of VfmulA64: arm64.emitVFmul(ctx.buf.data, rd, ra, rb, single)
    else:        arm64.emitVFmla(ctx.buf.data, rd, ra, rb, single)

  of VdupA64:
    # (vdup D S bits?) — broadcast S's lane 0 to every lane of D; trailing
    # lane-bits literal as in `vfadd`.
    inc n
    var single = isA64FpSingle(n, ctx)
    let rd = parseFloatOperandA64(n, ctx)
    let rn = parseFloatOperandA64(n, ctx)
    if n.kind == IntLit:
      single = int(n.intVal) == 32
      inc n
    arm64.emitVDup(ctx.buf.data, rd, rn, single)

  of VaddvA64:
    # (vaddv D S bits?) — horizontal fp add of S's lanes into the scalar D;
    # trailing lane-bits literal as in `vfadd`.
    inc n
    var single = isA64FpSingle(n, ctx)
    let rd = parseFloatOperandA64(n, ctx)
    let rn = parseFloatOperandA64(n, ctx)
    if n.kind == IntLit:
      single = int(n.intVal) == 32
      inc n
    arm64.emitVAddv(ctx.buf.data, rd, rn, single)

  of VeorA64:
    # (veor D A B) — 16-byte xor; `(veor X X X)` zeroes X.
    inc n
    let rd = parseFloatOperandA64(n, ctx)
    let ra = parseFloatOperandA64(n, ctx)
    let rb = parseFloatOperandA64(n, ctx)
    arm64.emitVEor(ctx.buf.data, rd, ra, rb)

  of BA64:
    inc n
    let op = parseOperandA64(n, ctx)
    if op.typ.kind != UIntT: error("Branch target must be label", n)
    checkForwardJump(ctx, op.label, n)
    arm64.emitB(ctx.buf, op.label)
  of BlA64:
    inc n
    let op = parseOperandA64(n, ctx)
    if op.typ.kind != UIntT: error("Branch target must be label", n)
    arm64.emitBL(ctx.buf, op.label)

  of CbzA64, CbnzA64:
    # (cbz S L) / (cbnz S L) — branch on S being zero / non-zero. Unlike every
    # `b.cc` above these read no flags, so they stand in for a whole `cmp S, #0`
    # plus conditional branch. Register-only by encoding (no immediate, no memory);
    # the value is compared as a full 64-bit register, which is what arkham's
    # sign-/zero-extension invariant makes correct for a narrower type too.
    let isZero = instTag == CbzA64
    inc n
    let src = parseOperandA64(n, ctx)
    if src.kind != okReg: error("CBZ/CBNZ source must be a register", n)
    checkComparable(src.typ, (if isZero: "cbz" else: "cbnz"), start)
    let lab = parseOperandA64(n, ctx)
    if lab.typ.kind != UIntT: error("Branch target must be label", n)
    checkForwardJump(ctx, lab.label, n)
    if isZero: arm64.emitCbz(ctx.buf, src.reg, lab.label)
    else: arm64.emitCbnz(ctx.buf, src.reg, lab.label)

  of BeqA64:
    inc n
    let op = parseOperandA64(n, ctx)
    if op.typ.kind != UIntT: error("Branch target must be label", n)
    checkForwardJump(ctx, op.label, n)
    arm64.emitBeq(ctx.buf, op.label)

  of BneA64:
    inc n
    let op = parseOperandA64(n, ctx)
    if op.typ.kind != UIntT: error("Branch target must be label", n)
    checkForwardJump(ctx, op.label, n)
    arm64.emitBne(ctx.buf, op.label)

  of BltA64:
    inc n
    let op = parseOperandA64(n, ctx)
    if op.typ.kind != UIntT: error("Branch target must be label", n)
    checkForwardJump(ctx, op.label, n)
    arm64.emitBlt(ctx.buf, op.label)

  of BleA64:
    inc n
    let op = parseOperandA64(n, ctx)
    if op.typ.kind != UIntT: error("Branch target must be label", n)
    checkForwardJump(ctx, op.label, n)
    arm64.emitBle(ctx.buf, op.label)

  of BgtA64:
    inc n
    let op = parseOperandA64(n, ctx)
    if op.typ.kind != UIntT: error("Branch target must be label", n)
    checkForwardJump(ctx, op.label, n)
    arm64.emitBgt(ctx.buf, op.label)

  of BgeA64:
    inc n
    let op = parseOperandA64(n, ctx)
    if op.typ.kind != UIntT: error("Branch target must be label", n)
    checkForwardJump(ctx, op.label, n)
    arm64.emitBge(ctx.buf, op.label)

  of BloA64:
    inc n
    let op = parseOperandA64(n, ctx)
    if op.typ.kind != UIntT: error("Branch target must be label", n)
    checkForwardJump(ctx, op.label, n)
    arm64.emitBlo(ctx.buf, op.label)

  of BlsA64:
    inc n
    let op = parseOperandA64(n, ctx)
    if op.typ.kind != UIntT: error("Branch target must be label", n)
    checkForwardJump(ctx, op.label, n)
    arm64.emitBls(ctx.buf, op.label)

  of BhiA64:
    inc n
    let op = parseOperandA64(n, ctx)
    if op.typ.kind != UIntT: error("Branch target must be label", n)
    checkForwardJump(ctx, op.label, n)
    arm64.emitBhi(ctx.buf, op.label)

  of BhsA64:
    inc n
    let op = parseOperandA64(n, ctx)
    if op.typ.kind != UIntT: error("Branch target must be label", n)
    checkForwardJump(ctx, op.label, n)
    arm64.emitBhs(ctx.buf, op.label)

  of StpA64:
    # (stp (rt1) (rt2) (rn) offset) → STP rt1, rt2, [rn, #offset]!  (pre-index)
    inc n
    let rt1 = parseRegisterA64(n)
    let rt2 = parseRegisterA64(n)
    let rn = parseRegisterA64(n)
    if n.kind != IntLit: error("stp expects an integer offset", n)
    let off = int32(getInt(n)); inc n
    arm64.emitStp(ctx.buf.data, rt1, rt2, rn, off)
    if ctx.inPrologue and rn == arm64.SP and off < 0:
      # `stp rt1, rt2, [sp, #-N]!` — the AArch64 prologue's pair push. rt1 lands
      # at the new bottom of the frame, rt2 8 bytes above it.
      ctx.cfiStep(-off, [int32(ord(rt1)), int32(ord(rt2))])

  of LdpA64:
    # (ldp (rt1) (rt2) (rn) offset) → LDP rt1, rt2, [rn], #offset  (post-index)
    inc n
    let rt1 = parseRegisterA64(n)
    let rt2 = parseRegisterA64(n)
    let rn = parseRegisterA64(n)
    if n.kind != IntLit: error("ldp expects an integer offset", n)
    let off = int32(getInt(n)); inc n
    arm64.emitLdp(ctx.buf.data, rt1, rt2, rn, off)

  of FstpA64:
    # (fstp (dt1) (dt2) (rn) offset) → STP Dt1, Dt2, [Xn, #offset]!  (pre-index)
    inc n
    let rt1 = parseFloatRegisterA64(n)
    let rt2 = parseFloatRegisterA64(n)
    let rn = parseRegisterA64(n)
    if n.kind != IntLit: error("fstp expects an integer offset", n)
    let off = int32(getInt(n)); inc n
    arm64.emitFstpPre(ctx.buf.data, rt1, rt2, rn, off)
    if ctx.inPrologue and rn == arm64.SP and off < 0:
      ctx.cfiStep(-off, [int32(ord(rt1)), int32(ord(rt2))], floats = true)  # see `StpA64`

  of FldpA64:
    # (fldp (dt1) (dt2) (rn) offset) → LDP Dt1, Dt2, [Xn], #offset  (post-index)
    inc n
    let rt1 = parseFloatRegisterA64(n)
    let rt2 = parseFloatRegisterA64(n)
    let rn = parseRegisterA64(n)
    if n.kind != IntLit: error("fldp expects an integer offset", n)
    let off = int32(getInt(n)); inc n
    arm64.emitFldpPost(ctx.buf.data, rt1, rt2, rn, off)

  of NoA64Inst:
    error("Invalid ARM64 instruction", start)

# ── Cortex-M (ARMv7E-M / Thumb-2) instruction selection ─────────────────────
#
# The counterpart of `genInstA64`, against `thumb2.nim`'s encoders. Two things
# differ from the AArch64 half and drive most of the shape below:
#
#  * the word is 4 bytes, so a "register" is 32 bits and `RegisterT` is declared
#    at 32 — a `(i 64)` local genuinely does not fit one and is rejected by name
#    rather than silently truncated (see M4 in doc/cortex_m.md);
#  * Cortex-M reuses the `(r0)`..`(r12)`/`(sp)`/`(lr)` spellings that already
#    exist for the other targets, so `rawTagIsMReg` — not the x86 or a64
#    classifier — is what decides whether a tag is a register HERE.

proc tagToFloatRegisterM(t: TagEnum; n: Cursor): thumb2.FloatRegister =
  if not rawTagIsMFloatReg(t):
    error("Expected a Cortex-M floating-point register", n)
    return thumb2.S0
  thumb2.FloatRegister(int(t) - int(S0TagId))

proc parseFloatRegisterM(n: var Cursor): thumb2.FloatRegister =
  if n.kind != TagLit or not rawTagIsMFloatReg(n.tag):
    error("Expected a Cortex-M floating-point register", n)
  result = tagToFloatRegisterM(n.tag, n)
  inc n

proc tagToRegisterM(t: TagEnum; n: Cursor): thumb2.Register =
  if rawTagIsMFloatReg(t):
    error("Expected an integer register, got a floating-point one", n)
    return thumb2.R0
  let regTag = tagToMReg(t)
  result =
    case regTag
    of R0MR: thumb2.R0
    of R1MR: thumb2.R1
    of R2MR: thumb2.R2
    of R3MR: thumb2.R3
    of R4MR: thumb2.R4
    of R5MR: thumb2.R5
    of R6MR: thumb2.R6
    of R7MR: thumb2.R7
    of R8MR: thumb2.R8
    of R9MR: thumb2.R9
    of R10MR: thumb2.R10
    of R11MR: thumb2.R11
    of R12MR: thumb2.R12
    of SpMR: thumb2.SP
    of LrMR: thumb2.LR
    else:
      error("Expected a Cortex-M register", n)
      thumb2.R0

proc parseRegisterM(n: var Cursor): thumb2.Register =
  if n.kind != TagLit or not rawTagIsMGpr(n.tag):
    error("Expected a Cortex-M register", n)
  result = tagToRegisterM(n.tag, n)
  inc n

type
  OperandM = object
    kind: OperandKind
    reg: thumb2.Register
    freg: thumb2.FloatRegister   ## the s-register, when `isFloat`
    isFloat: bool                ## the operand names an FPv4-SP register
    typ: Type
    immVal: int64
    mem: thumb2.MemoryOperand
    argName: SymId
    label: LabelId
    isCode: bool          ## the label names CODE (a proc), not data. Its address
                          ## must carry the Thumb bit — see `rkTMovwMovtFunc`.
    gvarSym: Symbol       ## non-nil if the operand is a global's (.bss) address

proc mRegType(): Type {.inline.} =
  ## The "any type that fits a register" type, at the Cortex-M width. 32, not 64:
  ## `compatible` uses `regBits div 8` as the size bound, so declaring 64 here
  ## would let a `(i 64)` value bind to a 32-bit register unnoticed.
  Type(kind: RegisterT, regBits: 32)

proc checkRegWidthM(t: Type; what: string; n: Cursor) =
  ## Reject a value too wide for one Thumb register BY NAME. 64-bit scalars are
  ## the expected case here and they are not an error in the input — they are a
  ## backend feature that does not exist yet (M4: register pairs, adds/adcs).
  ## Truncating them silently is the one outcome that must not happen.
  if t == nil: return
  if t.kind == TypeKind.FloatT:
    # A DOUBLE is not a missing feature, it is missing hardware: Cortex-M4F's
    # FPv4-SP is single precision only, and there is no `.f64` instruction to
    # lower to. Refusing beats dragging in a softfloat library nobody asked for.
    if t.bits > 32:
      error("Cortex-M: " & what & " is a " & $t.bits & "-bit float; this core's " &
            "FPv4-SP unit is SINGLE precision only (see M5 in doc/cortex_m.md)", n)
    return
  if t.kind in {TypeKind.IntT, TypeKind.UIntT} and t.bits > 32:
    error("Cortex-M: " & what & " is " & $t.bits & " bits; a 64-bit scalar lives " &
          "in memory here and cannot be bound to a register (see M4 in " &
          "doc/cortex_m.md)", n)

proc argWordTypeM(p: ptr Param): Type =
  ## The type of ONE argument register of `p`. An aggregate spread over several
  ## registers has no per-word Leng type, and neither does a 64-bit scalar split
  ## across a register PAIR — each half is a machine word. Reporting the param's
  ## own `(i 64)` for such a half is what would make `(mov (arg x 0) …)` look
  ## like a 64-bit register move to `checkRegWidthM`.
  if p.typ.kind in {TypeKind.ObjectT, TypeKind.ArrayT, TypeKind.UnionT} or
     p.regs.len > 1:
    mRegType()
  else: p.typ

proc parseOperandM(n: var Cursor; ctx: var GenContext): OperandM =
  if n.kind == TagLit:
    let t = n.tag
    if rawTagIsMFloatReg(t):
      result.isFloat = true
      result.freg = parseFloatRegisterM(n)
      result.typ = Type(kind: TypeKind.FloatT, bits: 32)
      if result.freg in ctx.mFRegBindings:
        error("Register " & $result.freg & " is bound to variable '" &
              ctx.mFRegBindings[result.freg] & "', use the variable name instead", n)
    elif rawTagIsMGpr(t):
      result.reg = parseRegisterM(n)
      result.typ = mRegType()
      # A raw use of a register that currently hosts a named local is a code
      # generator bug — it silently clobbers the value. Spell the name instead.
      if result.reg in ctx.mRegBindings:
        error("Register " & $result.reg & " is bound to variable '" &
              ctx.mRegBindings[result.reg] & "', use the variable name instead", n)
    elif t == NilTagId:
      result.kind = okImm
      result.immVal = 0
      result.typ = Type(kind: TypeKind.NilT)
      inc n
    elif t == ArgTagId:
      # `(arg name [k])` — an outgoing argument. In a REGISTER it names that
      # register; on the STACK it yields the byte OFFSET within the outgoing
      # argument area, for use inside `(mem (sp) (arg name))`.
      if not ctx.inCall:
        error("(arg ...) can only be used inside a prepare block", n)
      var argName = SymId(0)
      var wordIdx = 0
      into n:
        if n.kind != Symbol: error("Expected argument name in (arg ...)", n)
        argName = getSymId(n)
        inc n
        if n.hasMore and n.kind == IntLit:
          wordIdx = int(getInt(n))
          inc n
      let paramPtr = findParam(ctx.callContext.typ, argName)
      if paramPtr == nil:
        error("Unknown argument: " & ctx.nameOf(argName), n)
      if paramPtr.typ.isOnStack:
        var offset = ctx.callContext.stackArgBase
        for p in ctx.callContext.typ.params:
          if p.typ.isOnStack:
            if p.name == argName: break
            offset += slots.alignedSize(p.typ)
        result.kind = okImm
        result.argName = argName
        result.immVal = int64(offset + wordIdx * asmWordSize())
        result.typ = paramPtr.typ
      else:
        if wordIdx >= paramPtr.regs.len:
          error("argument word index out of range for " & ctx.nameOf(argName), n)
        result.kind = okArg
        result.argName = argName
        result.reg = tagToRegisterM(paramPtr.regs[wordIdx], n)
        result.typ = argWordTypeM(paramPtr)
    elif t == ResTagId:
      # `(res name)` — a call's result, readable only after the call.
      if not ctx.inCall:
        error("(res ...) can only be used inside a prepare block", n)
      inc n
      if n.kind != Symbol: error("Expected result name in (res ...)", n)
      let resName = getSymId(n)
      inc n
      if not ctx.callContext.callEmitted:
        error("(res ...) can only be used after (call) or (extcall)", n)
      let resPtr = findResult(ctx.callContext.typ, resName)
      if resPtr == nil: error("Unknown result: " & ctx.nameOf(resName), n)
      if resName in ctx.callContext.resultsSet:
        error("Result already bound: " & ctx.nameOf(resName), n)
      ctx.callContext.resultsSet.incl(resName)
      result.reg = tagToRegisterM(resPtr.reg, n)
      result.typ = resPtr.typ
    elif t == CsizeTagId:
      # `(csize)` — the outgoing stack-argument area of the CURRENT call. The
      # fixed-frame model reserves that area once in the prologue, so nothing
      # adjusts SP per call and this is only ever read as a size.
      if not ctx.inCall:
        error("(csize) can only be used inside a prepare block", n)
      result.kind = okImm
      result.immVal = int64(ctx.callContext.stackArgSize)
      result.typ = Type(kind: TypeKind.IntLitT, bits: 32, litVal: result.immVal)
      into n:
        while n.hasMore: skip n
    elif t == SsizeTagId:
      # `(ssize)` / `(ssize N)` — the frame size, patched once the frame is known.
      result.kind = okSsize
      result.typ = Type(kind: TypeKind.IntLitT, bits: 32)
      into n:
        if n.hasMore and n.kind == IntLit:
          result.immVal = getInt(n)
          inc n
    elif t == CastTagId:
      # `(cast T <operand>)` — a RETYPE, no instruction. Reinterpreting a register
      # as `(aptr T)` is how the code generator reaches an array through a pointer,
      # so this arm is what makes `(at (cast (aptr T) reg) idx)` resolve at all.
      inc n
      let castType = parseType(n, ctx.scope, ctx)
      var op = parseOperandM(n, ctx)
      op.typ = castType
      result = op
      return
    elif t == DotTagId:
      # `(dot <base> <field>)` — fold the field's offset onto the base address.
      # The result is typed `PtrT(fieldType)`: an embedded sub-object sits AT
      # base+offset rather than behind a loaded pointer, which is what lets
      # `(dot (dot o inner) a)` keep accumulating instead of dereferencing.
      inc n
      let baseOp = parseOperandM(n, ctx)
      if n.kind != Symbol: error("Expected field name in dot expression", n)
      let fieldName = getSym(n)
      inc n
      var objType: Type
      var baseReg = thumb2.R0
      var baseOffset: int32 = 0
      var baseIndex = thumb2.R0
      var baseShift = 0
      var baseHasIndex = false
      if baseOp.typ.kind == TypeKind.PtrT:
        objType = resolvedBase(baseOp.typ, ctx, n)
        if objType.kind notin {TypeKind.ObjectT, TypeKind.UnionT}:
          error("Cannot access field of non-object/union type " & $objType, n)
        if baseOp.kind == okMem:
          # A NESTED access: fold onto the inner base+offset(+index) rather than
          # treating the inner base register as the pointer, which would lose the
          # inner displacement.
          baseReg = baseOp.mem.base
          baseOffset = baseOp.mem.offset
          baseIndex = baseOp.mem.index
          baseShift = baseOp.mem.shift
          baseHasIndex = baseOp.mem.hasIndex
        else:
          baseReg = baseOp.reg
      elif baseOp.kind == okMem and baseOp.typ.kind in {TypeKind.ObjectT, TypeKind.UnionT}:
        objType = baseOp.typ
        baseReg = baseOp.mem.base
        baseOffset = baseOp.mem.offset
      elif baseOp.kind == okMem and baseOp.typ.kind == TypeKind.StackOffT and
           baseOp.typ.offType.kind in {TypeKind.ObjectT, TypeKind.UnionT}:
        objType = baseOp.typ.offType
        baseReg = baseOp.mem.base
        baseOffset = baseOp.mem.offset
      else:
        error("dot requires pointer to object/union or stack object/union, got " &
              $baseOp.typ, n)
      var fieldOffset = 0
      var fieldType: Type = nil
      for (fname, ftype, foff) in objType.fields:
        if fname == fieldName:
          fieldType = ftype
          fieldOffset = foff
          break
      if fieldType == nil:
        error("Field '" & fieldName & "' not found in " & $objType.kind, n)
      result.kind = okMem
      result.mem = thumb2.MemoryOperand(base: baseReg,
                                        offset: baseOffset + int32(fieldOffset),
                                        hasIndex: baseHasIndex, index: baseIndex,
                                        shift: baseShift)
      result.typ = Type(kind: TypeKind.PtrT, base: fieldType)
    elif t == AtTagId:
      # `(at <base> <index>)` folds to a scaled-index LDR/STR operand, or
      # `(at <base> <index> <scratch>)` when the element stride is not one of the
      # four LDR scales — then the caller supplies a register and WE compute
      # `base + index*stride` into it.
      into n:
        let baseOp = parseOperandM(n, ctx)
        let indexOp = parseOperandM(n, ctx)
        if not isIntegerType(indexOp.typ):
          error("Array index must be integer type, got " & $indexOp.typ, n)
        var elemType: Type
        var baseReg = thumb2.R0
        var baseOffset: int32 = 0
        var baseHasIndex = false
        if baseOp.typ.kind == TypeKind.AptrT:
          elemType = resolvedBase(baseOp.typ, ctx, n)
          baseReg = baseOp.reg
        elif baseOp.typ.kind == TypeKind.PtrT and
             resolvedBase(baseOp.typ, ctx, n).kind == TypeKind.ArrayT:
          elemType = resolvedBase(baseOp.typ, ctx, n).elem
          if baseOp.kind == okMem:
            baseReg = baseOp.mem.base
            baseOffset = baseOp.mem.offset
            baseHasIndex = baseOp.mem.hasIndex
          else:
            baseReg = baseOp.reg
        elif baseOp.kind == okMem and baseOp.typ.kind == TypeKind.ArrayT:
          elemType = baseOp.typ.elem
          baseReg = baseOp.mem.base
          baseOffset = baseOp.mem.offset
        elif baseOp.kind == okMem and baseOp.typ.kind == TypeKind.StackOffT and
             baseOp.typ.offType.kind == TypeKind.ArrayT:
          elemType = baseOp.typ.offType.elem
          baseReg = baseOp.mem.base
          baseOffset = baseOp.mem.offset
        else:
          error("at requires aptr, pointer-to-array, or stack array, got " &
                $baseOp.typ, n)
        let stride = asmSizeOf(elemType)

        var scratchReg = thumb2.R0
        var hasScratch = false
        if n.hasMore:
          let scratchOp = parseOperandM(n, ctx)
          if scratchOp.kind notin {okReg, okArg}:
            error("at: 3-operand scratch must be a register", n)
          scratchReg = scratchOp.reg
          hasScratch = true

        if hasScratch:
          if indexOp.kind notin {okReg, okArg}:
            error("at: 3-operand form expects a register index", n)
          if baseHasIndex:
            error("at: 3-operand form cannot extend a base that already has an index", n)
          # `scratch == base` is fatal: the multiply writes scratch (== base)
          # before the add reads the base, so the base is gone and the address is
          # wild. `scratch == index` is fine — the stride goes through IP, so the
          # index survives the multiply.
          if scratchReg == baseReg:
            error("at: 3-operand stride scratch aliases the base register (" &
                  $baseReg & ") — the base is clobbered before use (codegen bug)", n)
          if stride > 0 and (stride and (stride - 1)) == 0:
            # A power-of-two stride is a SHIFT: no constant, no multiply.
            var k = 0
            var t2 = stride
            while t2 > 1: (t2 = t2 shr 1; inc k)
            if k == 0: thumb2.emitMovReg(ctx.buf.data, scratchReg, indexOp.reg)
            else: thumb2.emitLslImm(ctx.buf.data, scratchReg, indexOp.reg, k)
          else:
            # The stride constant goes into IP, never into `scratchReg`: the caller
            # may hand a scratch that ALIASES the index, and materializing the
            # stride there would destroy the index before the multiply.
            thumb2.emitMovImm32(ctx.buf.data, thumb2.IP, uint32(stride))
            thumb2.emitMul(ctx.buf.data, scratchReg, indexOp.reg, thumb2.IP)
          thumb2.emitAdd3(ctx.buf.data, scratchReg, baseReg, scratchReg)
          result.kind = okMem
          result.mem = thumb2.MemoryOperand(base: scratchReg, offset: baseOffset)
          result.typ = Type(kind: TypeKind.PtrT, base: elemType)
        elif indexOp.kind == okImm:
          # A constant index folds straight into the displacement.
          result.kind = okMem
          result.mem = thumb2.MemoryOperand(
            base: baseReg,
            offset: baseOffset + int32(indexOp.immVal * stride),
            hasIndex: baseHasIndex, index: thumb2.R0, shift: 0)
          result.typ = Type(kind: TypeKind.PtrT, base: elemType)
        else:
          if baseHasIndex:
            error("at: base already carries an index; use the 3-operand form", n)
          if stride notin [1, 2, 4, 8]:
            error("at: element stride " & $stride & " is not an LDR/STR scale; " &
                  "use the 3-operand form with a scratch register", n)
          var shift = 0
          var t2 = stride
          while t2 > 1: (t2 = t2 shr 1; inc shift)
          result.kind = okMem
          result.mem = thumb2.MemoryOperand(base: baseReg, offset: baseOffset,
                                            hasIndex: true, index: indexOp.reg,
                                            shift: shift)
          result.typ = Type(kind: TypeKind.PtrT, base: elemType)
        while n.hasMore: skip n
      return
    elif t == MemTagId:
      # `(mem <base> [offset | field-symbol | (arg name)])`, or `(mem <lvalue>)`
      # where the lvalue is a `(dot …)`/`(at …)` that already folded to an address.
      #
      # `into` BOUNDS the cursor to this node's children — without it the
      # optional-offset check reads into the following sibling, and a
      # register-bound name after a `(mem base)` store destination gets eaten as
      # if it were an offset. Same reasoning as the a64 and x64 handlers.
      #
      # Nothing inside the `into` may `return`: it is a template whose scope-exit
      # bookkeeping a `return` jumps straight past, leaving the cursor inside a
      # scope it has left. That surfaces later as nifcore's "advancing past end
      # of scope", nowhere near the cause.
      into n:
        if n.kind == TagLit and (n.tag == DotTagId or n.tag == AtTagId):
          # The fold already produced the address and typed it `PtrT(elem)`;
          # dereferencing is just unwrapping that pointer to the value's type.
          let addrOp = parseOperandM(n, ctx)
          if addrOp.kind != okMem: error("mem requires an address expression", n)
          if addrOp.typ.kind != TypeKind.PtrT:
            error("mem requires pointer type, got " & $addrOp.typ, n)
          result = addrOp
          result.typ = resolvedBase(addrOp.typ, ctx, n)
        else:
          let base = parseOperandM(n, ctx)
          if base.kind == okMem:
            # A stack variable used as a base: its slot IS the address.
            result.mem = base.mem
          elif base.kind notin {okReg, okArg}:
            error("(mem ...) base must be a register", n)
          else:
            result.mem = thumb2.MemoryOperand(base: base.reg, offset: 0)
          if n.hasMore and n.kind == TagLit and n.tag == ArgTagId:
            # `(mem (sp) (arg name))` — the slot of an OUTGOING stack argument.
            let argOff = parseOperandM(n, ctx)
            if argOff.kind != okImm:
              error("(arg ...) in mem must denote a stack argument", n)
            result.mem.offset += int32(argOff.immVal)
          elif n.hasMore and n.kind == IntLit:
            result.mem.offset += int32(getInt(n))
            inc n
          elif n.hasMore and n.kind == Symbol:
            # A stack PARAMETER's name: its offset in the incoming argument area.
            let fname = getSym(n)
            let fsym = lookupWithAutoImport(ctx, ctx.scope, fname, n)
            if fsym == nil: error("Unknown symbol in (mem ...): " & fname, n)
            result.mem.offset += int32(fsym.offset)
            inc n
          result.kind = okMem
          result.typ =
            if base.kind == okMem and base.typ != nil and
               base.typ.kind == TypeKind.StackOffT:
              base.typ.offType
            elif base.typ != nil and base.typ.kind in {TypeKind.PtrT, TypeKind.AptrT}:
              resolvedBase(base.typ, ctx, n)
            else: mRegType()
        while n.hasMore: skip n
      return
    else:
      error("Unsupported Cortex-M operand", n)
  elif n.kind == IntLit:
    result.kind = okImm
    result.immVal = getInt(n)
    result.typ = Type(kind: IntLitT, bits: 32, litVal: result.immVal)
    inc n
  elif n.kind == Symbol:
    let name = getSym(n)
    let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
    if sym == nil: error("Unknown symbol: " & name, n)
    case sym.kind
    of skVar, skParam:
      if sym.typ.isOnStack:
        result.kind = okMem
        result.mem = thumb2.MemoryOperand(base: thumb2.SP, offset: int32(sym.offset))
        result.typ = sym.typ
      elif sym.reg != InvalidTagId and rawTagIsMFloatReg(sym.reg):
        result.isFloat = true
        result.freg = tagToFloatRegisterM(sym.reg, n)
        result.typ = sym.typ
      elif sym.reg != InvalidTagId:
        result.reg = tagToRegisterM(sym.reg, n)
        result.typ = sym.typ
        if result.reg in ctx.clobberedM:
          error("Variable '" & name & "' lives in " & $result.reg &
                ", which a call clobbered; its value is gone", n)
      else:
        error("Variable has no location: " & name, n)
      inc n
    of skLabel:
      result.reg = thumb2.R0
      result.label = LabelId(sym.offset)
      result.typ = Type(kind: TypeKind.UIntT, bits: 32)
      inc n
    of skRodata, skProc:
      if sym.offset == -1:
        let labId = ctx.buf.createLabel()
        sym.offset = int(labId)
        result.label = labId
      else:
        result.label = LabelId(sym.offset)
      result.isCode = sym.kind == skProc
      result.reg = thumb2.R0
      result.typ = Type(kind: TypeKind.UIntT, bits: 32)
      inc n
    of skGvar:
      result.gvarSym = sym
      result.reg = thumb2.R0
      result.typ = Type(kind: TypeKind.UIntT, bits: 32)
      inc n
    of skTvar:
      error("Cortex-M has no thread-local storage: '" & name & "'", n)
    else:
      error("Cannot use symbol '" & name & "' as an operand", n)
  else:
    error("Expected operand", n)

proc parseDestM(n: var Cursor; ctx: var GenContext): OperandM =
  if n.kind == TagLit and rawTagIsMFloatReg(n.tag):
    result.isFloat = true
    result.freg = parseFloatRegisterM(n)
    result.typ = Type(kind: TypeKind.FloatT, bits: 32)
    if result.freg in ctx.mFRegBindings:
      error("Register " & $result.freg & " is bound to variable '" &
            ctx.mFRegBindings[result.freg] & "', use the variable name instead", n)
  elif n.kind == TagLit and rawTagIsMGpr(n.tag):
    result.reg = parseRegisterM(n)
    result.typ = mRegType()
    if result.reg in ctx.mRegBindings:
      error("Register " & $result.reg & " is bound to variable '" &
            ctx.mRegBindings[result.reg] & "', use the variable name instead", n)
  elif n.kind == TagLit and n.tag == ArgTagId:
    # Binding a REGISTER argument inside a prepare block. Unlike an ordinary
    # register destination this deliberately skips the `mRegBindings` check: the
    # argument register is exactly where the value must go, and the call is about
    # to clobber it anyway.
    if not ctx.inCall:
      error("(arg ...) can only be used inside a prepare block", n)
    var argName = SymId(0)
    var wordIdx = 0
    into n:
      if n.kind != Symbol: error("Expected argument name in (arg ...)", n)
      argName = getSymId(n)
      inc n
      if n.hasMore and n.kind == IntLit:
        wordIdx = int(getInt(n))
        inc n
    let paramPtr = findParam(ctx.callContext.typ, argName)
    if paramPtr == nil: error("Unknown argument: " & ctx.nameOf(argName), n)
    if paramPtr.typ.isOnStack:
      error("Stack argument '" & ctx.nameOf(argName) &
            "' cannot be a direct destination; use (mem (sp) (arg " &
            ctx.nameOf(argName) & "))", n)
    if wordIdx == 0:
      if argName in ctx.callContext.argsSet:
        error("Argument already set: " & ctx.nameOf(argName), n)
      ctx.callContext.argsSet.incl(argName)
    if wordIdx >= paramPtr.regs.len:
      error("argument word index out of range for " & ctx.nameOf(argName), n)
    result.kind = okArg
    result.argName = argName
    result.reg = tagToRegisterM(paramPtr.regs[wordIdx], n)
    result.typ = argWordTypeM(paramPtr)
  elif n.kind == TagLit and (n.tag == MemTagId or n.tag == CastTagId):
    # `(cast T (mem …))` as a DESTINATION retypes — and thereby sizes — the
    # store, exactly as it does on the read side. This is how a 64-bit value's
    # two halves are addressed: the slot is `(i 64)`, each half is a
    # `(cast (u 32) (mem slot 0|4))`, and the cast is what says so rather than a
    # silent truncation of a 64-bit typed access down to one word.
    let op = parseOperandM(n, ctx)
    if op.kind != okMem: error("Expected memory destination", n)
    result = op
  elif n.kind == Symbol:
    let name = getSym(n)
    let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
    if sym == nil: error("Unknown symbol: " & name, n)
    if sym.kind in {skVar, skParam}:
      if sym.typ.isOnStack:
        result.kind = okMem
        result.mem = thumb2.MemoryOperand(base: thumb2.SP, offset: int32(sym.offset))
        result.typ = sym.typ
      elif sym.reg != InvalidTagId and rawTagIsMFloatReg(sym.reg):
        result.isFloat = true
        result.freg = tagToFloatRegisterM(sym.reg, n)
        result.typ = sym.typ
      elif sym.reg != InvalidTagId:
        result.reg = tagToRegisterM(sym.reg, n)
        result.typ = sym.typ
        ctx.clobberedM.excl(result.reg)   # writing a fresh value un-clobbers it
      else:
        error("Variable has no location: " & name, n)
      inc n
    else:
      error("Expected variable or register as destination", n)
  else:
    error("Expected destination", n)

proc regOfM(op: OperandM; what: string; n: Cursor): thumb2.Register =
  ## `okArg` counts: an argument bound to a register IS that register, it just
  ## carries the extra bookkeeping that the prepare block checks.
  if op.kind notin {okReg, okArg}: error(what & " must be a register", n)
  op.reg

proc condOfFlagM(flag: X64Flag; n: Cursor): thumb2.Condition =
  ## The Thumb condition a `(zf)`/`(nz)`/… flag tag selects. asm-NIF spells
  ## conditions with the x86 flag vocabulary on every target (AArch64 does the
  ## same); ARM's flags are N/Z/C/V, and the mapping is exact for the four.
  case flag
  of ZfO: thumb2.CondEQ
  of NzO: thumb2.CondNE
  of CfO: thumb2.CondHS      # C set == unsigned higher-or-same
  of NcO: thumb2.CondLO
  of SfO: thumb2.CondMI      # N set == negative
  of NsO: thumb2.CondPL
  of OfO: thumb2.CondVS
  of NoO: thumb2.CondVC
  else:
    error("Cortex-M: unsupported flag condition " & $flag, n)
    thumb2.CondEQ

proc emitBranchM(ctx: var GenContext; cond: thumb2.Condition; target: LabelId) =
  if cond == thumb2.CondAL: thumb2.emitB(ctx.buf, target)
  else: thumb2.emitBcond(ctx.buf, cond, target)

proc memWidthM(t: Type): tuple[width: thumb2.MemWidth; signed: bool] =
  ## The ACCESS WIDTH a typed memory operand implies, and whether a load of it
  ## sign-extends. A `(mem …)` carries the pointee / field / slot type, so a
  ## narrow integer must load with `ldrb`/`ldrh` (sign- or zero-extending) and
  ## store only its low bits.
  ##
  ## Without this every access was a full 32-bit `ldr`: reading one byte of a
  ## `(u 8)` array returned that byte AND the three after it, which is not a
  ## crash and not a type error — just a wrong value, and only for programs that
  ## happen to look at sub-word data.
  ##
  ## A stack slot is its content type behind a `(stackoff …)` wrapper; unwrap it
  ## and size by what the slot HOLDS, exactly as `memWidthOpc` does for AArch64.
  var ty = t
  if ty != nil and ty.kind == TypeKind.StackOffT: ty = ty.offType
  if ty == nil: return (thumb2.MemWord, false)
  case ty.kind
  of TypeKind.BoolT: (thumb2.MemByte, false)
  of TypeKind.IntT:
    if ty.bits == 8: (thumb2.MemByte, true)
    elif ty.bits == 16: (thumb2.MemHalf, true)
    else: (thumb2.MemWord, false)
  of TypeKind.UIntT:
    if ty.bits == 8: (thumb2.MemByte, false)
    elif ty.bits == 16: (thumb2.MemHalf, false)
    else: (thumb2.MemWord, false)
  else: (thumb2.MemWord, false)     # pointer, aggregate, register-typed: a word

proc emitMemAccessM(ctx: var GenContext; rt: thumb2.Register;
                    mem: thumb2.MemoryOperand; width: thumb2.MemWidth;
                    isLoad: bool; signed = false; n: Cursor) =
  ## THE one place a `(mem …)` operand becomes a load or a store, so the scaled
  ## index that `(at …)` folds in cannot be silently dropped by a caller that
  ## only looked at base+offset.
  ##
  ## Thumb-2's register-index form carries no displacement, so a memory operand
  ## with BOTH an index and a non-zero offset is materialized into IP first. IP is
  ## the AAPCS32 scratch and hosts no value, so this needs no spill.
  if not mem.hasIndex:
    if thumb2.fitsLoadStoreImm(mem.offset):
      thumb2.emitLoadStoreImm(ctx.buf.data, rt, mem.base, mem.offset, width,
                              isLoad = isLoad, signed = signed)
      return
    # Past the 12-bit displacement — a frame bigger than 4 KB. The address is
    # computed into IP, the AAPCS32 scratch that hosts no value. Unless IP is
    # already the value being moved, which is the one case with no register left
    # and therefore an error rather than a wrong address.
    if rt == thumb2.IP:
      error("Cortex-M: a " & $mem.offset & "-byte displacement needs the IP " &
            "scratch to compute, and IP already holds the value being moved", n)
    thumb2.emitMovImm32(ctx.buf.data, thumb2.IP, uint32(mem.offset))
    thumb2.emitAdd3(ctx.buf.data, thumb2.IP, mem.base, thumb2.IP)
    thumb2.emitLoadStoreImm(ctx.buf.data, rt, thumb2.IP, 0, width,
                            isLoad = isLoad, signed = signed)
  elif mem.offset == 0:
    thumb2.emitLoadStoreReg(ctx.buf.data, rt, mem.base, mem.index, width,
                            isLoad = isLoad, shift = mem.shift, signed = signed)
  else:
    if rt == thumb2.IP:
      error("Cortex-M: indexed access with a displacement cannot target IP", n)
    thumb2.emitAddImm(ctx.buf.data, thumb2.IP, mem.base, uint32(mem.offset))
    thumb2.emitLoadStoreReg(ctx.buf.data, rt, thumb2.IP, mem.index, width,
                            isLoad = isLoad, shift = mem.shift, signed = signed)

const MFpScratch = thumb2.S30
  ## The FPv4-SP counterpart of IP: a float register the SELECTOR may always use
  ## as a transient. `vcvt` between an integer and a float goes through the FPU,
  ## so `(fcvtzs <gpr> <sreg>)` needs somewhere to put the converted value before
  ## moving it across — and the source may still be live. arkham keeps s30 out of
  ## every pool for this, exactly as it keeps r12 out for IP.

proc emitVfpMemAccessM(ctx: var GenContext; sd: thumb2.FloatRegister;
                       mem: thumb2.MemoryOperand; isLoad: bool; n: Cursor) =
  ## THE one place a `(mem …)` becomes a VLDR/VSTR, so a folded scaled index
  ## cannot be silently dropped. VLDR has no register-index form at all, so an
  ## indexed operand is materialized into IP first — the AAPCS32 scratch, which
  ## hosts no value.
  if not mem.hasIndex:
    if thumb2.fitsVldrVstrImm(mem.offset):
      thumb2.emitVldrVstr(ctx.buf.data, sd, mem.base, mem.offset, isLoad)
    else:
      # VLDR reaches only +/-1020, so this happens far sooner than it does for an
      # integer access. IP is always free here: the value is in a FLOAT register.
      thumb2.emitMovImm32(ctx.buf.data, thumb2.IP, uint32(mem.offset))
      thumb2.emitAdd3(ctx.buf.data, thumb2.IP, mem.base, thumb2.IP)
      thumb2.emitVldrVstr(ctx.buf.data, sd, thumb2.IP, 0, isLoad)
    return
  if mem.shift == 0:
    thumb2.emitAdd3(ctx.buf.data, thumb2.IP, mem.base, mem.index)
  else:
    thumb2.emitLslImm(ctx.buf.data, thumb2.IP, mem.index, mem.shift)
    thumb2.emitAdd3(ctx.buf.data, thumb2.IP, mem.base, thumb2.IP)
  if not thumb2.fitsVldrVstrImm(mem.offset):
    thumb2.emitAddImm(ctx.buf.data, thumb2.IP, thumb2.IP, uint32(mem.offset))
    thumb2.emitVldrVstr(ctx.buf.data, sd, thumb2.IP, 0, isLoad)
    return
  thumb2.emitVldrVstr(ctx.buf.data, sd, thumb2.IP, mem.offset, isLoad)

proc loadToRegM(ctx: var GenContext; dest: thumb2.Register; op: OperandM; n: Cursor) =
  ## Materialize `op` into `dest`. The one place that decides how each operand
  ## KIND reaches a register, so no arm has to repeat it.
  case op.kind
  of okReg, okArg:
    if op.reg != dest: thumb2.emitMovReg(ctx.buf.data, dest, op.reg)
  of okImm:
    thumb2.emitMovImm32(ctx.buf.data, dest, uint32(op.immVal))
  of okSsize:
    # The frame size is not known until the whole proc has been read, so emit a
    # MOVW/MOVT pair with a zero immediate and record the site. The pair is a
    # FIXED 8 bytes whatever the final value, so patching never has to resize an
    # instruction — which is what lets this work at all, since every label
    # position downstream is already fixed by then.
    ctx.ssizePatches.add((ctx.buf.data.len, int(op.immVal)))
    thumb2.emitMovImm16(ctx.buf.data, dest, 0)
    thumb2.emitMovt(ctx.buf.data, dest, 0)
  of okMem:
    let (w, sx) = memWidthM(op.typ)
    ctx.emitMemAccessM(dest, op.mem, w, isLoad = true, signed = sx, n = n)
  of okLabel:
    thumb2.emitMovwMovtAbs(ctx.buf, dest, op.label)
  else:
    error("Cortex-M: operand cannot be loaded into a register", n)

proc storeFromRegM(ctx: var GenContext; src: thumb2.Register; dst: OperandM; n: Cursor) =
  if dst.kind != okMem: error("Cortex-M: expected a memory destination", n)
  # Sized by the DESTINATION's type: a narrow store must write only its low
  # bytes, or it takes the neighbouring fields with it.
  let (w, _) = memWidthM(dst.typ)
  ctx.emitMemAccessM(src, dst.mem, w, isLoad = false, n = n)

proc scratchM(ctx: GenContext; avoid: varargs[thumb2.Register]): thumb2.Register =
  ## A register the selector may use as a transient. r12 (IP) is reserved for
  ## exactly this by AAPCS32 — it is call-clobbered and no local is ever bound to
  ## it — so a bridge never has to spill anything. Falls back to lr only if the
  ## caller is already using IP for one of the operands.
  result = thumb2.IP
  for a in avoid:
    if a == result: result = thumb2.LR
  discard ctx

proc genStmtM(n: var Cursor; ctx: var GenContext)
proc genInstM(n: var Cursor; ctx: var GenContext)

proc genIteM(n: var Cursor; ctx: var GenContext) =
  inc n
  let lElse = ctx.buf.createLabel()
  let lEnd = ctx.buf.createLabel()
  let oldClobbered = ctx.clobberedM
  if n.kind == Symbol:
    let name = getSym(n)
    let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
    if sym == nil or sym.kind != skCfvar:
      error("Expected cfvar in ite condition: " & name, n)
    if sym.used: error("Control flow variable '" & name & "' used more than once", n)
    sym.used = true
    inc n
    thumb2.emitB(ctx.buf, lElse)
    ctx.buf.defineLabel(LabelId(sym.offset))
  elif n.kind == TagLit:
    let flagTag = tagToX64Flag(n.tag)
    inc n
    # Branch to the ELSE arm when the condition does NOT hold, so the then-arm
    # falls through.
    ctx.emitBranchM(thumb2.invert(condOfFlagM(flagTag, n)), lElse)
  else:
    error("Expected cfvar or flag condition in ite", n)
  genStmtM(n, ctx)
  let thenClobbered = ctx.clobberedM
  thumb2.emitB(ctx.buf, lEnd)
  ctx.clobberedM = oldClobbered
  ctx.buf.defineLabel(lElse)
  genStmtM(n, ctx)
  let elseClobbered = ctx.clobberedM
  ctx.buf.defineLabel(lEnd)
  # A register clobbered on EITHER branch is clobbered after the merge.
  ctx.clobberedM = thenClobbered + elseClobbered

proc genLoopM(n: var Cursor; ctx: var GenContext) =
  inc n
  # The only form arkham emits: `(loop (stmts …))`, whose back-edge nifasm adds
  # here. The body carries a FORWARD branch to a break label defined after the
  # loop, so no backward branch ever appears in the input.
  if atTag(n, StmtsTagId):
    let lStart = ctx.buf.createLabel()
    ctx.buf.defineLabel(lStart)
    genStmtM(n, ctx)
    thumb2.emitB(ctx.buf, lStart)
    return
  error("Cortex-M: only the `(loop (stmts …))` form is supported", n)

proc genJtrueM(n: var Cursor; ctx: var GenContext) =
  ## `(jtrue <cfvar>… <flag>)` — branch to the cfvar's label when the flag holds.
  inc n
  var target = LabelId(-1)
  while n.hasMore and n.kind == Symbol:
    let name = getSym(n)
    let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
    if sym == nil or sym.kind != skCfvar: error("Expected cfvar in jtrue: " & name, n)
    if int(target) == -1: target = LabelId(sym.offset)
    sym.used = true
    inc n
  if int(target) == -1: error("jtrue needs a cfvar", n)
  if n.kind != TagLit: error("Expected a flag condition in jtrue", n)
  let flagTag = tagToX64Flag(n.tag)
  inc n
  ctx.emitBranchM(condOfFlagM(flagTag, n), target)

proc bindFRegM(ctx: var GenContext; name: string; typ: Type; regTag: TagEnum;
               freg: thumb2.FloatRegister) =
  ## The FPv4-SP twin of `bindRegM`: bind an s-register to a typed name, killing
  ## its prior tenant so a stale value shows up as "Unknown symbol" rather than
  ## as a silent clobber.
  if freg in ctx.mFRegBindings:
    ctx.scope.undefine(ctx.symIdOf(ctx.mFRegBindings[freg]))
    ctx.mFRegBindings.del(freg)
  let sym = Symbol(name: ctx.symIdOf(name), kind: skVar, typ: typ)
  sym.reg = regTag
  ctx.mFRegBindings[freg] = name
  ctx.scope.define(sym)

proc bindRegM(ctx: var GenContext; name: string; typ: Type; regTag: TagEnum;
              reg: thumb2.Register) =
  ## Bind `reg` to the typed name `name`, KILLING its prior tenant first — so a
  ## later use of a value wrongly left in that register is an "Unknown symbol"
  ## error rather than a silent clobber. The "(re)bind implies a kill" rule that
  ## `rebind` and `withreg` share; mirrors `bindRegA64`/`bindRegX64`.
  if reg in ctx.mRegBindings:
    ctx.scope.undefine(ctx.symIdOf(ctx.mRegBindings[reg]))
    ctx.mRegBindings.del(reg)
  ctx.clobberedM.excl(reg)   # a fresh binding abandons a prior call's clobber
  let sym = Symbol(name: ctx.symIdOf(name), kind: skVar, typ: typ)
  sym.reg = regTag
  ctx.mRegBindings[reg] = name
  ctx.scope.define(sym)

proc parseRebindHeaderM(n: var Cursor; ctx: var GenContext):
                       tuple[name: string; reg: thumb2.Register] =
  ## Parse `:name TYPE (reg)` (cursor already inside the node) and establish the
  ## binding. Shared by `rebind` and `withreg`.
  if n.kind != SymbolDef: error("Expected name for rebind/withreg", n)
  let name = symName(n); inc n
  let typ = parseType(n, ctx.scope, ctx)
  checkRegWidthM(typ, "rebind of '" & name & "'", n)
  if n.kind == TagLit and rawTagIsMFloatReg(n.tag):
    let fTag = n.tag
    let f = tagToFloatRegisterM(fTag, n)
    inc n
    bindFRegM(ctx, name, typ, fTag, f)
    return (name, thumb2.R0)          # the GPR half of the result is unused here
  if n.kind != TagLit or not rawTagIsMGpr(n.tag):
    error("Expected a register for rebind/withreg", n)
  let regTag = n.tag
  let reg = tagToRegisterM(regTag, n)
  inc n
  bindRegM(ctx, name, typ, regTag, reg)
  result = (name, reg)

const MCallClobbers = {thumb2.R0 .. thumb2.R3, thumb2.IP, thumb2.LR}
  ## What a call destroys under AAPCS32: r0–r3 (arguments and return), r12 (IP,
  ## the intra-procedure scratch) and lr (which `bl` overwrites with the return
  ## address). r4–r11 are callee-saved, which is where a value that must survive
  ## a call belongs.

proc callClobbersM(ctx: GenContext): set[thumb2.Register] =
  ## What THIS callee declares it destroys, falling back to the full volatile set
  ## when the signature declared nothing. An empty declared list is meaningful —
  ## it is what lets a caller keep a value in a caller-saved register across a
  ## call that provably preserves it.
  let t = ctx.callContext.typ
  if t != nil and t.kind == ProcT and t.hasClobberDecl: t.clobbersM
  else: MCallClobbers

proc genPrepareM(n: var Cursor; ctx: var GenContext) =
  ## `(prepare target … (call) …)` — the call-site protocol. Sets up the call
  ## context so every `(arg …)` is checked against the target's signature, then
  ## verifies on the way out that every register parameter was bound and that a
  ## call was actually emitted.
  var hdr = n
  inc hdr
  if hdr.kind != Symbol: error("Expected proc symbol, got " & $hdr.kind, hdr)
  let name = getSym(hdr)
  let sym = lookupWithAutoImport(ctx, ctx.scope, name, hdr)
  if sym == nil: error("Unknown symbol: " & name, hdr)

  let outerCall = ctx.callContext
  if outerCall.state != CallContextState.Disabled and
     outerCall.stackArgSize > outerCall.stackArgBase:
    error("Nested prepare blocks are not allowed when the outer call passes " &
          "arguments on the stack: both would write the one outgoing area", hdr)
  ctx.callContext = CallContext(
    state: CallContextState.NormalCall,
    target: name,
    argsSet: initHashSet[SymId](),
    resultsSet: initHashSet[SymId](),
    callEmitted: false)

  case sym.kind
  of skProc:
    ctx.callContext.typ = sym.typ
  of skGvar, skVar, skParam:
    if sym.typ.kind != ProcT:
      error("Expected proc symbol, got " & $sym.kind, hdr)
    ctx.callContext.typ = sym.typ
    ctx.callContext.indirect = true
  of skExtProc:
    error("Cortex-M is a bare-metal target: there is nothing to link against, " &
          "so `extproc` (" & name & ") has no meaning here", hdr)
  of skSysProc:
    error("Cortex-M has no OS and therefore no syscalls: '" & name & "'", hdr)
  else:
    error("Expected proc symbol, got " & $sym.kind, hdr)

  ctx.callContext.stackArgSize = computeStackArgSize(ctx.callContext.typ)
  if ctx.callContext.stackArgSize > ctx.reservedArgArea:
    error("outgoing stack-argument area (" & $ctx.callContext.stackArgSize &
          " bytes) exceeds the reserved frame area (" & $ctx.reservedArgArea &
          " bytes); call target not visible to the frame pre-scan", hdr)

  into n:
    skip n                   # the target symbol
    while n.hasMore:
      genInstM(n, ctx)

  for param in ctx.callContext.typ.params:
    if not param.typ.isOnStack and param.name notin ctx.callContext.argsSet:
      error("Missing argument: " & ctx.nameOf(param.name), hdr)
  for res in ctx.callContext.typ.results:
    if res.name notin ctx.callContext.resultsSet:
      error("Missing result binding: " & ctx.nameOf(res.name), hdr)
  if not ctx.callContext.callEmitted:
    error("Missing (call) in prepare block", hdr)

  ctx.callContext = outerCall
  if outerCall.state == CallContextState.Disabled:
    ctx.callContext.state = CallContextState.Disabled

proc genCallMarkerM(n: var Cursor; ctx: var GenContext) =
  if not ctx.inCall:
    error("(call) can only be used inside a prepare block", n)
  if ctx.callContext.callEmitted:
    error("Multiple (call) instructions in prepare block", n)
  let sym = lookupWithAutoImport(ctx, ctx.scope, ctx.callContext.target, n)
  ctx.clobberedM.incl callClobbersM(ctx)

  if ctx.callContext.indirect:
    # Through a function pointer. r12 (IP) is the AAPCS32 scratch: caller-saved
    # and never an argument register, so loading the target there cannot disturb
    # the arguments already staged in r0–r3.
    if sym.kind in {skVar, skParam} and sym.reg != InvalidTagId:
      # The register holds the code address itself — call straight through it.
      thumb2.emitBlx(ctx.buf.data, tagToRegisterM(sym.reg, n))
    elif sym.kind == skGvar:
      # r12 = &fnptr (patched with the global's absolute address), then load the
      # pointer and call it. IP is the AAPCS32 scratch and never an argument
      # register, so the arguments already staged in r0–r3 are untouched.
      ctx.gvarSites.add (ctx.buf.data.len, sym)
      thumb2.emitMovImm16(ctx.buf.data, thumb2.IP, 0)
      thumb2.emitMovt(ctx.buf.data, thumb2.IP, 0)
      thumb2.emitLdr(ctx.buf.data, thumb2.IP, thumb2.IP, 0'i32)
      thumb2.emitBlx(ctx.buf.data, thumb2.IP)
    elif sym.kind in {skVar, skParam} and sym.typ.isOnStack:
      # A function pointer in a stack slot: load it into IP and call through it.
      thumb2.emitLdr(ctx.buf.data, thumb2.IP, thumb2.SP, int32(sym.offset))
      thumb2.emitBlx(ctx.buf.data, thumb2.IP)
    else:
      error("Cortex-M: indirect call through " & $sym.kind & " is not supported yet", n)
    ctx.callContext.callEmitted = true
    inc n
    return

  var labId: LabelId
  if sym.offset == -1:
    labId = ctx.buf.createLabel()
    sym.offset = int(labId)
  else:
    labId = LabelId(sym.offset)
  thumb2.emitBl(ctx.buf, labId)
  ctx.callContext.callEmitted = true
  inc n

proc genInstM(n: var Cursor; ctx: var GenContext) =
  if n.kind != TagLit: error("Expected instruction", n)
  let instTag = tagToMInst(n.tag)
  let start = n

  case tagToNifasmDecl(n.tag)
  of CfvarD:
    inc n
    if n.kind != SymbolDef: error("Expected cfvar name", n)
    let name = symName(n)
    inc n
    let cfvarLabel = ctx.buf.createLabel()
    ctx.scope.define(Symbol(name: ctx.symIdOf(name), kind: skCfvar,
                            typ: Type(kind: TypeKind.BoolT),
                            offset: int(cfvarLabel), used: false))
    return
  of VarD:
    inc n
    if n.kind != SymbolDef: error("Expected var name", n)
    let name = symName(n)
    inc n
    var reg = InvalidTagId
    var onStack = false
    var slotAlign = asmWordSize()
    if n.kind == TagLit:
      let locTag = n.tag
      if rawTagIsMFloatReg(locTag):
        let f = tagToFloatRegisterM(locTag, n)
        inc n
        let ftyp = parseType(n, ctx.scope, ctx)
        checkRegWidthM(ftyp, "variable '" & name & "'", n)
        if f in ctx.mFRegBindings:
          error("Register " & $f & " is already bound to variable '" &
                ctx.mFRegBindings[f] & "', kill it first before reusing", n)
        bindFRegM(ctx, name, ftyp, locTag, f)
        return
      if rawTagIsMGpr(locTag):
        let r = tagToRegisterM(locTag, n)
        if r == thumb2.IP:
          error("Cannot bind a variable to r12 (reserved as the AAPCS32 IP scratch)", n)
        if r == thumb2.SP or r == thumb2.LR:
          error("Cannot bind a variable to " & $r, n)
        reg = locTag
        inc n
      elif locTag == STagId:
        onStack = true
        slotAlign = parseSlotAlign(n)
      else:
        error("Expected location", n)
    else:
      error("Expected location", n)
    let baseTyp = parseType(n, ctx.scope, ctx)
    let sym = Symbol(name: ctx.symIdOf(name), kind: skVar)
    if onStack:
      sym.typ = Type(kind: TypeKind.StackOffT, offType: baseTyp)
      sym.offset = ctx.slots.allocSlotUp(baseTyp, slotAlign)
    else:
      checkRegWidthM(baseTyp, "variable '" & name & "'", n)
      sym.typ = baseTyp
      sym.reg = reg
      let targetReg = tagToRegisterM(reg, n)
      if targetReg in ctx.mRegBindings:
        error("Register " & $targetReg & " is already bound to variable '" &
              ctx.mRegBindings[targetReg] & "', kill it first before reusing", n)
      ctx.mRegBindings[targetReg] = name
      ctx.clobberedM.excl(targetReg)
    ctx.scope.define(sym)
    return
  of NoDecl:
    discard "handled by `case instTag` below"
  else:
    raiseAssert("Unhandled declaration tag in Cortex-M selector")

  # An overflowing mnemonic's id is a leading child; skip it once so every arm's
  # own `inc n` still lands on operand 0. Same step as genInstX64/genInstA64.
  if isEscapedTag(n): inc n

  template bin3(emitter: untyped) =
    ## `(op3 D A B)` → `D = A op B`, with B folded through a scratch when it is
    ## not already a register (Thumb-2's 3-operand forms take no immediate).
    inc n
    let d = parseDestM(n, ctx)
    let a = parseOperandM(n, ctx)
    let b = parseOperandM(n, ctx)
    let dr = regOfM(d, "destination", start)
    let ar = regOfM(a, "first source", start)
    var br: thumb2.Register
    if b.kind == okReg: br = b.reg
    else:
      br = ctx.scratchM(dr, ar)
      ctx.loadToRegM(br, b, start)
    emitter(ctx.buf.data, dr, ar, br)

  template bin2(emitter: untyped) =
    ## `(op D S)` → `D = D op S`, the two-operand spelling. Thumb-2 is a
    ## three-operand ISA, so this is `op3 D, D, S`.
    inc n
    let d = parseDestM(n, ctx)
    let sOp = parseOperandM(n, ctx)
    let dr = regOfM(d, "destination", start)
    var sr: thumb2.Register
    if sOp.kind == okReg: sr = sOp.reg
    else:
      sr = ctx.scratchM(dr)
      ctx.loadToRegM(sr, sOp, start)
    emitter(ctx.buf.data, dr, dr, sr)

  template unary(emitter: untyped) =
    inc n
    let d = parseDestM(n, ctx)
    let sOp = parseOperandM(n, ctx)
    let dr = regOfM(d, "destination", start)
    var sr: thumb2.Register
    if sOp.kind == okReg: sr = sOp.reg
    else:
      sr = ctx.scratchM(dr)
      ctx.loadToRegM(sr, sOp, start)
    emitter(ctx.buf.data, dr, sr)

  template loadStore(width: thumb2.MemWidth; loading: bool; signExt: bool) =
    ## The template parameters are deliberately NOT called `isLoad`/`signed`:
    ## those are the encoder's own parameter names, and a template argument of
    ## the same name substitutes into the named-argument syntax below, turning
    ## `isLoad = true` into `true = true`.
    inc n
    if loading:
      let d = parseDestM(n, ctx)
      let sOp = parseOperandM(n, ctx)
      if sOp.kind != okMem: error("load source must be memory", start)
      ctx.emitMemAccessM(regOfM(d, "destination", start), sOp.mem, width,
                         isLoad = true, signed = signExt, n = start)
    else:
      let d = parseDestM(n, ctx)
      let sOp = parseOperandM(n, ctx)
      if d.kind != okMem: error("store destination must be memory", start)
      var sr: thumb2.Register
      if sOp.kind in {okReg, okArg}: sr = sOp.reg
      else:
        sr = ctx.scratchM(d.mem.base, d.mem.index)
        ctx.loadToRegM(sr, sOp, start)
      ctx.emitMemAccessM(sr, d.mem, width, isLoad = false, n = start)

  case instTag
  of StmtsM:
    loopInto n:
      genInstM(n, ctx)
  of ScopeM:
    let savedStackSize = ctx.slots.stackSize
    loopInto n:
      genInstM(n, ctx)
    ctx.slots.maxStackSize = max(ctx.slots.maxStackSize, ctx.slots.stackSize)
    ctx.slots.stackSize = savedStackSize
  of LabM:
    inc n
    if n.kind != SymbolDef: error("Expected label name", n)
    let name = symName(n)
    let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
    if sym == nil:
      let labId = ctx.buf.createLabel()
      ctx.scope.define(Symbol(name: ctx.symIdOf(name), kind: skLabel, offset: int(labId)))
      ctx.buf.defineLabel(labId)
      ctx.definedLabels.incl int(labId)
    elif sym.kind == skLabel:
      if sym.offset == -1:
        let labId = ctx.buf.createLabel()
        sym.offset = int(labId)
        ctx.buf.defineLabel(labId)
        ctx.definedLabels.incl int(labId)
      else:
        ctx.buf.defineLabel(LabelId(sym.offset))
        ctx.definedLabels.incl sym.offset
    else:
      error("Symbol is not a label", n)
    inc n
  of MovM:
    inc n
    let dest = parseDestM(n, ctx)
    let op = parseOperandM(n, ctx)
    if not movTypeOk(dest.kind, dest.typ, op.kind, op.typ):
      error("Type mismatch in mov: expected " & $dest.typ & ", got " & $op.typ, start)
    checkPtrStore(dest.typ, op.kind, op.typ, start)
    checkRegWidthM(dest.typ, "mov destination", start)
    if dest.kind == okMem:
      var sr: thumb2.Register
      if op.kind == okReg: sr = op.reg
      else:
        sr = ctx.scratchM(dest.mem.base)
        ctx.loadToRegM(sr, op, start)
      ctx.storeFromRegM(sr, dest, start)
    else:
      ctx.loadToRegM(regOfM(dest, "mov destination", start), op, start)
  of AdrM, LeaM:
    inc n
    let dest = parseDestM(n, ctx)
    let op = parseOperandM(n, ctx)
    let dr = regOfM(dest, "adr destination", start)
    if op.kind == okMem:
      # `(lea D <lvalue>)` — the ADDRESS, not the contents. A folded index has to
      # be added in explicitly here; there is no address-computing instruction on
      # Thumb-2 that takes a scaled index the way x86's `lea` does.
      if op.mem.base != dr: thumb2.emitMovReg(ctx.buf.data, dr, op.mem.base)
      if op.mem.offset != 0:
        thumb2.emitAddImm(ctx.buf.data, dr, dr, uint32(op.mem.offset))
      if op.mem.hasIndex:
        if op.mem.shift == 0:
          thumb2.emitAdd3(ctx.buf.data, dr, dr, op.mem.index)
        else:
          thumb2.emitLslImm(ctx.buf.data, thumb2.IP, op.mem.index, op.mem.shift)
          thumb2.emitAdd3(ctx.buf.data, dr, dr, thumb2.IP)
    elif op.gvarSym != nil:
      # A global lives in SRAM, nowhere near the code, so its address is
      # materialized ABSOLUTELY (MOVW+MOVT) rather than PC-relatively. The pair is
      # a fixed 8 bytes; the image writer patches its immediates once the .bss
      # layout is known, exactly as the AArch64 backend patches its adrp+add.
      ctx.gvarSites.add (ctx.buf.data.len, op.gvarSym)
      thumb2.emitMovImm16(ctx.buf.data, dr, 0)
      thumb2.emitMovt(ctx.buf.data, dr, 0)
    else:
      # A code/rodata label. MOVW+MOVT carries the ABSOLUTE address, so unlike
      # ADR it has no ±4 KB reach limit — a firmware image's load address is
      # fixed at link time, so there is nothing to be relative to.
      #
      # A PROC's address additionally carries the Thumb bit: `blx` to an even
      # address switches to ARM state, which M-profile does not have.
      if op.isCode: thumb2.emitMovwMovtFunc(ctx.buf, dr, op.label)
      else: thumb2.emitMovwMovtAbs(ctx.buf, dr, op.label)
  of CmpM:
    inc n
    let a = parseOperandM(n, ctx)
    let b = parseOperandM(n, ctx)
    let ar = regOfM(a, "cmp first operand", start)
    if b.kind == okImm and b.immVal >= 0 and thumb2.isModifiedImm(uint32(b.immVal)):
      thumb2.emitCmpImm(ctx.buf.data, ar, uint32(b.immVal))
    else:
      var br: thumb2.Register
      if b.kind == okReg: br = b.reg
      else:
        br = ctx.scratchM(ar)
        ctx.loadToRegM(br, b, start)
      thumb2.emitCmpReg(ctx.buf.data, ar, br)
  of TstM:
    inc n
    let a = parseOperandM(n, ctx)
    let b = parseOperandM(n, ctx)
    let ar = regOfM(a, "tst first operand", start)
    var br: thumb2.Register
    if b.kind == okReg: br = b.reg
    else:
      br = ctx.scratchM(ar)
      ctx.loadToRegM(br, b, start)
    thumb2.emitTstReg(ctx.buf.data, ar, br)
  of OrrM: bin2(thumb2.emitOrr3)
  of EorM: bin2(thumb2.emitEor3)
  of LslM: bin2(thumb2.emitLsl)
  of LsrM: bin2(thumb2.emitLsr)
  of AsrM: bin2(thumb2.emitAsr)
  # The W-forms are AArch64's 32-bit views of a 64-bit register. On Cortex-M a
  # register IS 32 bits, so each is simply its full-width counterpart — accepted
  # rather than rejected so the code generator need not know the difference.
  of AddwM: bin2(thumb2.emitAdd3)
  of SubwM: bin2(thumb2.emitSub3)
  of MulwM: bin2(thumb2.emitMul)
  of Addw3M: bin3(thumb2.emitAdd3)
  of Subw3M: bin3(thumb2.emitSub3)
  of Mulw3M: bin3(thumb2.emitMul)
  of AddM: bin2(thumb2.emitAdd3)
  of SubM: bin2(thumb2.emitSub3)
  of MulM: bin2(thumb2.emitMul)
  of AndM: bin2(thumb2.emitAnd3)
  of Add3M: bin3(thumb2.emitAdd3)
  of Sub3M: bin3(thumb2.emitSub3)
  of Mul3M: bin3(thumb2.emitMul)
  of And3M: bin3(thumb2.emitAnd3)
  of Orr3M: bin3(thumb2.emitOrr3)
  of Eor3M: bin3(thumb2.emitEor3)
  of Bic3M: bin3(thumb2.emitBic3)
  of Lsl3M: bin3(thumb2.emitLsl)
  of Lsr3M: bin3(thumb2.emitLsr)
  of Asr3M: bin3(thumb2.emitAsr)
  of Adds3M: bin3(thumb2.emitAddsCarry)
  of Adcs3M: bin3(thumb2.emitAdcs)
  of Subs3M: bin3(thumb2.emitSubsCarry)
  of Sbcs3M: bin3(thumb2.emitSbcs)
  of SdivM: bin3(thumb2.emitSdiv)
  of UdivM: bin3(thumb2.emitUdiv)
  of NegM: unary(thumb2.emitNeg)
  of MvnM: unary(thumb2.emitMvn)
  of ClzM: unary(thumb2.emitClz)
  of RbitM: unary(thumb2.emitRbit)
  of RevM: unary(thumb2.emitRev)
  of UxtbM: unary(thumb2.emitUxtb)
  of SxtbM: unary(thumb2.emitSxtb)
  of UxthM: unary(thumb2.emitUxth)
  of SxthM: unary(thumb2.emitSxth)
  of MlsM:
    # `(mls D A B C)` → D = C - A*B. The remainder half of a division.
    inc n
    let d = parseDestM(n, ctx)
    let a = parseOperandM(n, ctx)
    let b = parseOperandM(n, ctx)
    let c = parseOperandM(n, ctx)
    thumb2.emitMls(ctx.buf.data, regOfM(d, "destination", start),
                   regOfM(a, "operand A", start), regOfM(b, "operand B", start),
                   regOfM(c, "operand C", start))
  of UmullM, SmullM:
    # `(umull L H A B)` → the 64-bit product into the register PAIR L (low) / H (high).
    inc n
    let lo = parseDestM(n, ctx)
    let hi = parseDestM(n, ctx)
    let a = parseOperandM(n, ctx)
    let b = parseOperandM(n, ctx)
    let lr0 = regOfM(lo, "low destination", start)
    let hr = regOfM(hi, "high destination", start)
    if lr0 == hr: error("umull/smull need two DISTINCT destination registers", start)
    if instTag == UmullM:
      thumb2.emitUmull(ctx.buf.data, lr0, hr, regOfM(a, "operand A", start),
                       regOfM(b, "operand B", start))
    else:
      thumb2.emitSmull(ctx.buf.data, lr0, hr, regOfM(a, "operand A", start),
                       regOfM(b, "operand B", start))
  of LdrM:   loadStore(thumb2.MemWord, true, false)
  of StrM:   loadStore(thumb2.MemWord, false, false)
  of LdrbM:  loadStore(thumb2.MemByte, true, false)
  of StrbM:  loadStore(thumb2.MemByte, false, false)
  of LdrhM:  loadStore(thumb2.MemHalf, true, false)
  of StrhM:  loadStore(thumb2.MemHalf, false, false)
  of LdrsbM: loadStore(thumb2.MemByte, true, true)
  of LdrshM: loadStore(thumb2.MemHalf, true, true)
  of RebindM:
    # `(rebind :name TYPE (reg))` — bind until an explicit kill, the next rebind
    # of the same register, or proc end.
    into n:
      discard parseRebindHeaderM(n, ctx)
  of WithregM:
    # `(withreg :name TYPE (reg) body…)` — a block-scoped rebind, auto-killed at
    # the end of the body.
    into n:
      let h = parseRebindHeaderM(n, ctx)
      while n.hasMore: genInstM(n, ctx)
      if ctx.mRegBindings.getOrDefault(h.reg, "") == h.name:
        ctx.mRegBindings.del(h.reg)
      ctx.scope.undefine(ctx.symIdOf(h.name))
  of BeqM, BneM, BhsM, BloM, BltM, BlsM, BhiM, BgtM, BgeM, BleM:
    # The per-condition branch forms the code generator emits directly (as
    # opposed to `ite`/`jtrue`, which take a flag tag). Each maps to one Thumb
    # condition; the ±1 MB reach of B<cond>.W is the relocation's problem.
    inc n
    if n.kind != Symbol: error("conditional branch needs a label", start)
    let lbl = parseOperandM(n, ctx)
    let cond = case instTag
               of BeqM: thumb2.CondEQ
               of BneM: thumb2.CondNE
               of BhsM: thumb2.CondHS
               of BloM: thumb2.CondLO
               of BltM: thumb2.CondLT
               of BlsM: thumb2.CondLS
               of BhiM: thumb2.CondHI
               of BgtM: thumb2.CondGT
               of BgeM: thumb2.CondGE
               else: thumb2.CondLE
    thumb2.emitBcond(ctx.buf, cond, lbl.label)
  of PrepareM: genPrepareM(n, ctx)
  of CallM: genCallMarkerM(n, ctx)
  of IteM:  genIteM(n, ctx)
  of LoopM: genLoopM(n, ctx)
  of JtrueM: genJtrueM(n, ctx)
  of BM, BlM:
    inc n
    if n.kind != Symbol: error("b/bl needs a label or proc symbol", start)
    let op = parseOperandM(n, ctx)
    if instTag == BM: thumb2.emitB(ctx.buf, op.label)
    else: thumb2.emitBl(ctx.buf, op.label)
  of CbzM, CbnzM:
    # No CBZ/CBNZ encoder: their reach is +4..+126 bytes FORWARD only, which a
    # relocation pass cannot honour once anything moves. `cmp #0` + `b<cond>` is
    # two bytes larger and always correct.
    inc n
    let rOp = parseOperandM(n, ctx)
    let rr = regOfM(rOp, "cbz operand", start)
    if n.kind != Symbol: error("cbz/cbnz needs a label", start)
    let lbl = parseOperandM(n, ctx)
    thumb2.emitCmpImm(ctx.buf.data, rr, 0)
    ctx.emitBranchM((if instTag == CbzM: thumb2.CondEQ else: thumb2.CondNE), lbl.label)
  of BxM:
    inc n
    thumb2.emitBx(ctx.buf.data, parseRegisterM(n))
  of BlxM:
    inc n
    thumb2.emitBlx(ctx.buf.data, parseRegisterM(n))
  of RetM:
    inc n
    thumb2.emitRet(ctx.buf.data)
  of NopM:
    inc n
    thumb2.emitNop(ctx.buf.data)
  of WfiM:
    inc n
    thumb2.emitWfi(ctx.buf.data)
  of BkptM:
    inc n
    if n.kind != IntLit: error("bkpt needs an immediate", start)
    thumb2.emitBkpt(ctx.buf.data, uint8(getInt(n) and 0xFF))
    inc n
  # ── FPv4-SP ───────────────────────────────────────────────────────────────
  # Single precision only; a double is refused by `checkRegWidthM` long before
  # it can reach an encoder that has no `.f64` form to offer.
  of FmovM:
    # `(fmov D S)` is three instructions in one mnemonic, exactly as it is on
    # AArch64: fp<-fp, fp<-gpr and gpr<-fp. Which one is decided by the operand
    # REGISTER CLASSES, not by a separate tag.
    inc n
    let d = parseDestM(n, ctx)
    let sOp = parseOperandM(n, ctx)
    if d.isFloat and sOp.isFloat:
      thumb2.emitVmovReg(ctx.buf.data, d.freg, sOp.freg)
    elif d.isFloat:
      var sr: thumb2.Register
      if sOp.kind in {okReg, okArg} and not sOp.isFloat: sr = sOp.reg
      else:
        sr = ctx.scratchM()
        ctx.loadToRegM(sr, sOp, start)
      thumb2.emitVmovToFp(ctx.buf.data, d.freg, sr)
    elif sOp.isFloat:
      thumb2.emitVmovFromFp(ctx.buf.data, regOfM(d, "fmov destination", start),
                            sOp.freg)
    else:
      error("fmov needs a floating-point register on one side", start)
  of FaddM, FsubM, FmulM, FdivM:
    # `(fop D S)` — destructive on AArch64, three-operand on Thumb-2, so `D` is
    # repeated as the first source.
    inc n
    let d = parseDestM(n, ctx)
    let sOp = parseOperandM(n, ctx)
    if not d.isFloat or not sOp.isFloat:
      error("fadd/fsub/fmul/fdiv need floating-point registers", start)
    case instTag
    of FaddM: thumb2.emitVadd(ctx.buf.data, d.freg, d.freg, sOp.freg)
    of FsubM: thumb2.emitVsub(ctx.buf.data, d.freg, d.freg, sOp.freg)
    of FmulM: thumb2.emitVmul(ctx.buf.data, d.freg, d.freg, sOp.freg)
    else:     thumb2.emitVdiv(ctx.buf.data, d.freg, d.freg, sOp.freg)
  of FnegM:
    inc n
    let d = parseDestM(n, ctx)
    if not d.isFloat: error("fneg needs a floating-point register", start)
    thumb2.emitVneg(ctx.buf.data, d.freg, d.freg)
  of FcmpM:
    # VCMP writes FPSCR and the conditional branches read APSR, so a float
    # compare is always the PAIR. There is no float-condition branch to fuse it
    # into, which is why this cannot be split.
    inc n
    let d = parseOperandM(n, ctx)
    let sOp = parseOperandM(n, ctx)
    if not d.isFloat or not sOp.isFloat:
      error("fcmp needs floating-point registers", start)
    thumb2.emitVcmp(ctx.buf.data, d.freg, sOp.freg)
    thumb2.emitVmrsApsr(ctx.buf.data)
  of FldrM:
    inc n
    let d = parseDestM(n, ctx)
    let sOp = parseOperandM(n, ctx)
    if not d.isFloat: error("fldr destination must be a floating-point register", start)
    if sOp.kind != okMem: error("fldr source must be memory", start)
    ctx.emitVfpMemAccessM(d.freg, sOp.mem, isLoad = true, n = start)
  of FstrM:
    inc n
    let d = parseDestM(n, ctx)
    let sOp = parseOperandM(n, ctx)
    if d.kind != okMem: error("fstr destination must be memory", start)
    if not sOp.isFloat: error("fstr source must be a floating-point register", start)
    ctx.emitVfpMemAccessM(sOp.freg, d.mem, isLoad = false, n = start)
  of ScvtfM, UcvtfM:
    # `(scvtf D S)` — D fp, S integer. FPv4 converts inside the FPU, so the
    # integer crosses with VMOV first and is converted in place in D.
    inc n
    let d = parseDestM(n, ctx)
    let sOp = parseOperandM(n, ctx)
    if not d.isFloat: error("scvtf/ucvtf destination must be a float register", start)
    var sr: thumb2.Register
    if sOp.kind in {okReg, okArg} and not sOp.isFloat: sr = sOp.reg
    else:
      sr = ctx.scratchM()
      ctx.loadToRegM(sr, sOp, start)
    thumb2.emitVmovToFp(ctx.buf.data, d.freg, sr)
    thumb2.emitVcvtToF32(ctx.buf.data, d.freg, d.freg, signed = instTag == ScvtfM)
  of FcvtzsM, FcvtzuM:
    # `(fcvtzs D S)` — D integer, S fp. The converted value has to land in an fp
    # register before it can cross, and S may still be live, so it lands in the
    # selector's own float scratch.
    inc n
    let d = parseDestM(n, ctx)
    let sOp = parseOperandM(n, ctx)
    if not sOp.isFloat: error("fcvtzs/fcvtzu source must be a float register", start)
    thumb2.emitVcvtFromF32(ctx.buf.data, MFpScratch, sOp.freg,
                           signed = instTag == FcvtzsM)
    thumb2.emitVmovFromFp(ctx.buf.data, regOfM(d, "destination", start), MFpScratch)
  of DsbM:
    inc n
    thumb2.emitDsb(ctx.buf.data)
  of IsbM:
    inc n
    thumb2.emitIsb(ctx.buf.data)
  of KillM:
    # `(kill name…)` — end a register binding so the register may be rebound.
    inc n
    while n.hasMore and n.kind == Symbol:
      let name = getSym(n)
      let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
      if sym != nil and sym.reg != InvalidTagId:
        if rawTagIsMFloatReg(sym.reg):
          ctx.mFRegBindings.del(tagToFloatRegisterM(sym.reg, n))
        else:
          ctx.mRegBindings.del(tagToRegisterM(sym.reg, n))
      inc n
  of NoMInst:
    error("Cortex-M: unsupported instruction", start)
  else:
    error("Cortex-M: instruction '" & $instTag & "' is not implemented yet " &
          "(see doc/cortex_m.md)", start)

proc genStmtM(n: var Cursor; ctx: var GenContext) =
  genInstM(n, ctx)

proc genInstDispatch(n: var Cursor; ctx: var GenContext) {.inline.} =
  case ctx.arch
  of Arch.X64, Arch.WinX64:
    genInstX64(n, ctx)
  of Arch.A64, Arch.WinA64, Arch.LinuxA64:
    genInstA64(n, ctx)
  of Arch.CortexM:
    genInstM(n, ctx)

proc genInst(n: var Cursor; ctx: var GenContext) =
  let cfiBefore = ctx.buf.data.len
  ctx.prologueOp = false
  if not ctx.listing:
    genInstDispatch(n, ctx)
  else:
    # Render BEFORE the dispatch: `n` is advanced past the node by it. The NIF
    # renderer breaks lines; the listing is one TSV row per node, so flatten
    # runs of whitespace to single spaces (and drop the tabs a string literal
    # could otherwise smuggle into a column separator).
    var text = ""
    var sawSpace = true                          # leading whitespace is dropped
    for ch in toString(n, includeLineInfo = false):
      if ch in {' ', '\t', '\n', '\r'}:
        if not sawSpace: text.add ' '
        sawSpace = true
      else:
        text.add ch
        sawSpace = false
      if text.len >= ListingTextCap:
        text.add "…"
        break
    let start = ctx.buf.data.len
    let depth = ctx.listDepth
    inc ctx.listDepth
    genInstDispatch(n, ctx)
    dec ctx.listDepth
    let stop = ctx.buf.data.len
    if stop > start:                       # a node that emitted no bytes is not a row
      ctx.listRows.add ListingRow(start: start, stop: stop, depth: depth,
                                  procName: ctx.procName, text: text)
  # The prologue ends at the first instruction that EMITS CODE and is not one of
  # the frame-building forms. Judging it by emitted bytes rather than by tag is
  # what keeps the zero-code nodes between them — a `(var :x (s) T)` slot
  # declaration, a `(kill …)` — from cutting the run short.
  if ctx.inPrologue and not ctx.prologueOp and ctx.buf.data.len != cfiBefore:
    ctx.inPrologue = false

proc remapListing(ctx: var GenContext; posMap: seq[int]) =
  ## Carry the listing through one of the post-emission layout passes
  ## (`threadJumps` / `invertCondJumps` / `shortenX64Jumps`), each of which
  ## returns an old→new byte-position map. Same treatment `gvarSites` and
  ## `entryStubOffset` gets — without it every row would name a pre-relaxation
  ## address and the join to a profile would be silently wrong.
  ##
  ## Those passes DELETE code (a threaded-away jump, a folded `jcc`/`jmp` pair).
  ## A deleted byte's map entry is the position the deletion collapsed to, so such
  ## a row comes out empty (`start == stop`) and is dropped here: its instruction
  ## is not in the image any more.
  if not ctx.listing: return
  var keep = 0
  for k in 0 ..< ctx.listRows.len:
    let s = posMap[ctx.listRows[k].start]
    let e = posMap[ctx.listRows[k].stop]
    if e > s:
      ctx.listRows[keep] = ctx.listRows[k]
      ctx.listRows[keep].start = s
      ctx.listRows[keep].stop = e
      inc keep
  ctx.listRows.setLen keep

proc remapUnwind(ctx: var GenContext; posMap: seq[int]) =
  ## The debug-info twin of `remapListing`: carry every recorded proc range and
  ## CFI step through one layout pass. A `.symtab` entry or an FDE that still
  ## names a pre-relaxation address is worse than none — GDB would attribute the
  ## crash to a neighbouring proc rather than admit it does not know.
  for k in 0 ..< ctx.unwind.len:
    ctx.unwind[k].start = posMap[ctx.unwind[k].start]
    ctx.unwind[k].stop = posMap[ctx.unwind[k].stop]
    for s in 0 ..< ctx.unwind[k].steps.len:
      ctx.unwind[k].steps[s].at = posMap[ctx.unwind[k].steps[s].at]

proc writeListing(ctx: GenContext; path: string; textVaddr: int) =
  ## `--listing:FILE`: one TSV row per asm-NIF instruction node that survived into
  ## the image, as `vaddr<TAB>len<TAB>depth<TAB>proc<TAB>nif`, sorted by address
  ## then by depth. Rows NEST: a compound node (`ite`, `loop`, `prepare`) covers
  ## its children's bytes too, so a consumer attributing one address picks the row
  ## with the GREATEST depth that contains it — that is the node the bytes came
  ## from. The shallower rows are kept because the enclosing construct is often
  ## what you actually want to blame.
  ##
  ## `textVaddr` is the virtual address `.text` byte 0 lands at, so the addresses
  ## match `--symmap` and a disassembly of the finished image with no arithmetic
  ## on the consumer's side.
  var rows = ctx.listRows
  rows.sort(proc (x, y: ListingRow): int =
    result = cmp(x.start, y.start)
    if result == 0: result = cmp(x.depth, y.depth))
  var s = newStringOfCap(rows.len * 96)
  s.add "# nifasm --listing: vaddr\tlen\tdepth\tproc\tnif\n"
  s.add "# rows NEST; attribute an address to the DEEPEST row containing it.\n"
  s.add "# .text base 0x" & toHex(textVaddr, 6) &
        (if textVaddr == 0: " (addresses are __text-RELATIVE on this format)\n" else: "\n")
  for r in rows:
    s.add "0x" & toHex(textVaddr + r.start, 6)
    s.add '\t'; s.add $(r.stop - r.start)
    s.add '\t'; s.add $r.depth
    s.add '\t'; s.add r.procName
    s.add '\t'; s.add r.text
    s.add '\n'
  writeFile(path, s)

proc collectLabels(n: var Cursor; ctx: var GenContext; scope: Scope) =
  ## Pre-scan a cursor subtree and create placeholder symbols for labels.
  if n.kind == TagLit:
    if n.tag == LabTagId:
      var tmp = n
      inc tmp
      if tmp.kind == SymbolDef:
        let nameId = getSymId(tmp)
        var sym = scope.lookup(nameId)
        if sym == nil:
          let labId = ctx.buf.createLabel()
          sym = Symbol(name: nameId, kind: skLabel, offset: int(labId))
          scope.define(sym)
        elif sym.kind == skLabel and sym.offset == -1:
          sym.offset = int(ctx.buf.createLabel())
    loopInto n:
      collectLabels(n, ctx, scope)
  else:
    inc n

proc scanStackArgArea(n: var Cursor; ctx: var GenContext; scope: Scope; acc: var int) =
  ## Pre-scan a proc body for the largest outgoing stack-argument area any `(prepare …)`
  ## needs (AArch64 fixed-frame model). The result seeds the slot allocator so the area is
  ## reserved ONCE at the frame bottom: local `(s)` slots then sit ABOVE it and `(ssize)`
  ## includes it, so the caller writes `(mem (sp) (arg pN))` with no per-call `sub sp` and
  ## SP stays constant between prologue and epilogue. A target that doesn't resolve here
  ## (an indirect call through a not-yet-declared local fn-ptr) contributes 0; `genPrepareA64`
  ## guards against an under-reservation at emit time.
  if n.kind == TagLit:
    if n.tag == PrepareTagId:
      # A Win64 call owns the 32-byte shadow space at the bottom of the area whatever
      # its signature says — reserved even for a call with no stack argument at all,
      # and even for one whose target does not resolve here. Must match
      # `genPrepareX64`'s `stackArgBase`, which is what it checks against.
      let base = if ctx.arch == Arch.WinX64: WinShadowSpace else: 0
      acc = max(acc, base)
      var t = n; inc t                           # the call target symbol
      if t.kind == Symbol:
        let s = lookupWithAutoImport(ctx, scope, getSym(t), t)
        if s != nil and s.typ != nil and s.typ.kind == ProcT:
          acc = max(acc, base + computeStackArgSize(s.typ))
    loopInto n:
      scanStackArgArea(n, ctx, scope, acc)
  else:
    inc n

proc shiftCodePositions(ctx: var GenContext; at, by: int)   # defined below

proc pass2Proc(n: var Cursor; ctx: var GenContext) =
  let oldScope = ctx.scope
  ctx.scope = newScope(oldScope)

  # `into` bounds the cursor to the proc's own children, so walking to the body
  # can never run into the following decls (the main module's buffer continues
  # past this proc) and a body-less proc just iterates to its end.
  into n:
    if n.kind != SymbolDef:
      error("Expected symbol definition", n)
    let name = symName(n)
    ctx.procName = name
    gCurProc = name

    # Proc code must start 4-aligned: a lazily emitted rodata blob (arbitrary byte
    # length, e.g. a 2-byte string constant) may immediately precede this proc in
    # the text stream, and AArch64 instructions are fixed 4-byte words — a
    # misaligned body desynchronizes the whole following instruction stream.
    if ctx.arch in {Arch.A64, Arch.WinA64, Arch.LinuxA64, Arch.CortexM}:
      # Cortex-M needs only halfword alignment, but a 32-bit Thumb encoding
      # straddling a word boundary costs a cycle on some cores and nothing here
      # benefits from the two saved bytes, so it aligns like the others.
      while (ctx.buf.data.len and 3) != 0: ctx.buf.data.add 0'u8

    # Find/Create label for proc
    let sym = oldScope.lookup(getSymId(n))
    if sym.offset == -1:
      let lab = ctx.buf.createLabel()
      sym.offset = int(lab)
    ctx.buf.defineLabel(LabelId(sym.offset))
    ctx.definedLabels.clear()   # fresh backward-jump tracking per proc

    # Open this proc's debug-info record. The CFA at a proc's entry is fixed by
    # the ABI: on x86-64 the `call` has pushed the return address (CFA = SP+8),
    # on AArch64 it is still in the link register (CFA = SP).
    ctx.unwind.add ProcUnwind(name: ctx.nameOf(getSymId(n)),
                              start: ctx.buf.data.len, stop: -1)
    ctx.inPrologue = true
    # CFA at entry: on x86-64 the `call` pushed the return address (SP+8); on
    # AArch64 and Cortex-M it is still in the link register, so the CFA is SP.
    ctx.cfaOff = if ctx.arch in {Arch.A64, Arch.WinA64, Arch.LinuxA64, Arch.CortexM}: 0'i32
                 else: 8'i32

    # Initialize stack context
    ctx.slots = initSlotManager()
    ctx.ssizePatches = @[]
    # Clear register bindings at the start of each proc
    ctx.regBindings = initTable[x86.Register, string]()
    ctx.a64RegBindings = initTable[arm64.Register, string]()
    ctx.mRegBindings = initTable[thumb2.Register, string]()
    ctx.xmmBindings = initTable[x86.XmmRegister, string]()
    ctx.a64FRegBindings = initTable[arm64.FloatRegister, string]()
    # Each proc is a fresh control flow: no registers are clobbered on entry.
    # (Matters now that proc bodies are emitted back-to-back when bundling.)
    ctx.clobbered = {}
    ctx.clobberedA64 = {}
    ctx.clobberedM = {}
    ctx.lenient = false
    gLenient = false

    # Add params to scope.
    #
    # Stack-passed params live in the incoming argument area. On x86-64 that area
    # sits above the saved RBP and return address (RBP+16). On AArch64 the return
    # address is in LR (not on the stack) and the caller leaves SP pointing right
    # at the first stack arg, so incoming stack params are addressed SP-relative
    # from offset 0 (valid before the callee shifts SP).
    # Cortex-M shares AArch64's frame shape here: the return address is in LR
    # rather than on the stack, and the caller leaves SP pointing at the first
    # stack argument, so incoming stack params are SP-relative from offset 0.
    let isA64Proc = ctx.arch in {Arch.A64, Arch.WinA64, Arch.LinuxA64, Arch.CortexM}
    # …and on Win64 the caller's stack arguments start above the shadow space it also
    # reserved, so the callee's view of them shifts by the same amount.
    var paramOffset = if isA64Proc: 0
                      elif ctx.arch == Arch.WinX64: 16 + WinShadowSpace
                      else: 16
    for param in sym.typ.params:
      if param.typ.isOnStack:
        # param.typ is already StackOffT
        ctx.scope.define(Symbol(name: param.name, kind: skParam, typ: param.typ, offset: paramOffset))
        paramOffset += slots.alignedSize(param.typ.offType)
      else:
        ctx.scope.define(Symbol(name: param.name, kind: skParam, typ: param.typ, reg: param.reg))
        # Track register-passed params for the bound-register check. x86 spells a
        # register param by its name in the body, so a raw use of it is a code-gen bug
        # → reject it. The A64 backend instead reads its register params as raw `(xN)`
        # (a leaf param stays unnamed in its incoming arg register), so params are NOT
        # tracked there — only A64 register *locals* and `rebind`-bound scratch enter
        # `a64RegBindings`.
        if not isA64Proc and param.reg != InvalidTagId and not param.viaRegs:
          ctx.regBindings[tagToRegister(param.reg, n)] = ctx.nameOf(param.name)

    skip n   # past the proc name

    # Fixed-frame model — BOTH AArch64 and x86-64 use it here: reserve the largest
    # outgoing stack-argument area any call in this proc needs at the BOTTOM of the frame
    # BEFORE any local `(s)` slot is allocated, so locals land above it and `(ssize)`
    # covers it. The caller then passes stack args by writing `(mem (sp) (arg pN))` into
    # that region with NO per-call `sub sp` — SP is constant from prologue to epilogue, so
    # a stack-passed value (which can't sit in a register across a shift) is addressed at a
    # stable offset. This MUST run on x86-64 too: arkham emits the same `(mem (rsp)(arg
    # pN))`-into-`[rsp+off]` sequence with no per-call `sub rsp`, so without the reservation
    # the outgoing arg slots alias the caller's own locals at `[rsp+0…]` and clobber them
    # (e.g. a 6th integer arg overwrote a local `Info`'s first 8 bytes).
    ctx.reservedArgArea = 0
    block:
      var scanArgs = n
      var maxArgs = 0
      while scanArgs.hasMore:
        scanStackArgArea(scanArgs, ctx, ctx.scope, maxArgs)
      ctx.reservedArgArea = maxArgs
      ctx.slots.stackSize = max(ctx.slots.stackSize, maxArgs)

    # Emit the body — the `(stmts …)` child — and skip the signature sections
    # (already consumed in pass1). The `while hasMore` is bounded by the proc's
    # `into`, so it stops at the proc end naturally.
    while n.hasMore:
      if atTag(n, LenientTagId):
        # `(lenient)` precedes the body (takeSig consumed it in pass1); it
        # relaxes the structural checks for THIS proc only.
        ctx.lenient = true
        gLenient = true
        skip n
      elif atTag(n, StmtsTagId):
        var scan = n
        collectLabels(scan, ctx, ctx.scope)
        loopInto n:
          genInst(n, ctx)
      else:
        skip n

  # Check that all declared cfvars were used exactly once
  for cfvarName, cfvarSym in ctx.scope.syms:
    if cfvarSym.kind == skCfvar:
      if not cfvarSym.used:
        quit "[Error] Control flow variable '" & ctx.nameOf(cfvarName) & "' declared but never used in proc " & ctx.procName

  # Patch ssize. On x86 the placeholder is a raw imm32 in the instruction; on
  # AArch64 the immediate is a bit-field of a 32-bit instruction, so the patch
  # rewrites that field (MOVZ imm16 at [20:5]; ADD/SUB imm12 at [21:10]).
  # `(scope …)` blocks reclaim their slots (reset `stackSize`), so the FINAL
  # `stackSize` under-counts the frame. Reserve the peak seen at any point.
  let peakStackSize = max(ctx.slots.stackSize, ctx.slots.maxStackSize)
  let alignedStackSize = (peakStackSize + 15) and not 15
  let isA64 = ctx.arch in {Arch.A64, Arch.WinA64, Arch.LinuxA64}
  let isM = ctx.arch == Arch.CortexM
  var deadFrameAdjusts: seq[int] = @[]   ## frame `add`/`sub` halves that patch to #0
  for (pos, pad) in ctx.ssizePatches:
    # `pad` is the caller-supplied alignment correction from `(ssize N)`: the frame
    # `sub`/`add` folds the 16-alignment pad into the SAME instruction instead of
    # emitting a second `sub rsp, 8` / `add rsp, 8` around it. `alignedStackSize` is
    # 16-aligned, so `+ pad` lands the frame exactly where the separate pair did.
    let v = uint32(alignedStackSize + pad)
    if pos + 4 > ctx.buf.data.len: continue
    if isM:
      # A MOVW/MOVT pair, always 8 bytes, so no instruction changes length and no
      # position downstream moves. That is why the Cortex-M frame needs none of
      # the dead-adjust removal the AArch64 path does below — and why any frame
      # size at all fits, rather than the 12- or 16-bit immediate the other two
      # targets are limited to.
      if pos + 8 > ctx.buf.data.len: continue
      ctx.buf.data.patchThumbMovwMovtPair(pos, v)
      continue
    if isA64:
      var instr = uint32(ctx.buf.data[pos]) or (uint32(ctx.buf.data[pos+1]) shl 8) or
                  (uint32(ctx.buf.data[pos+2]) shl 16) or (uint32(ctx.buf.data[pos+3]) shl 24)
      if (instr shr 24) == 0xD2'u32:        # MOVZ Xd, #imm16 → imm16 at [20:5]
        if v > 0xFFFF'u32:
          quit "nifasm: stack frame of " & $alignedStackSize &
               " bytes exceeds the 16-bit `mov reg, (ssize)` immediate"
        instr = (instr and not (0xFFFF'u32 shl 5)) or ((v and 0xFFFF'u32) shl 5)
      else:
        # ADD/SUB Xd, Xn, #imm12 → imm12 at [21:10]. These come in PAIRS (see the
        # `okSsize` emit sites): the instruction carrying the `sh` bit takes the HIGH
        # 12 bits, the other the low 12. Masking both to `v and 0xFFF` is what silently
        # truncated every frame over 4095 bytes.
        if v > 0xFFFFFF'u32:
          quit "nifasm: stack frame of " & $alignedStackSize &
               " bytes exceeds the 24-bit ADD/SUB immediate pair"
        let half = if (instr and arm64.ShBit12) != 0: (v shr 12) and 0xFFF'u32
                   else: v and 0xFFF'u32
        instr = (instr and not (0xFFF'u32 shl 10)) or (half shl 10)
        # Either half of the pair can patch to ZERO, and then that whole instruction
        # does nothing: the HIGH one for every frame of 4095 bytes or less (the
        # common case — `sub sp, sp, #0, lsl #12`), the LOW one for a frame that is
        # an exact multiple of 4096 (`sub sp, sp, #0`, which disassembles as
        # `mov sp, sp`). It sits in every prologue AND every epilogue, so twice per
        # call, which is where it is least affordable. The frame size is only known
        # HERE, so it cannot be skipped at emit time — but it can be pruned now.
        if half == 0'u32 and not inFixedRange(ctx.buf, pos):
          deadFrameAdjusts.add pos
      ctx.buf.data[pos]   = byte(instr and 0xFF)
      ctx.buf.data[pos+1] = byte((instr shr 8) and 0xFF)
      ctx.buf.data[pos+2] = byte((instr shr 16) and 0xFF)
      ctx.buf.data[pos+3] = byte((instr shr 24) and 0xFF)
    else:
      ctx.buf.data[pos]   = byte(v and 0xFF)
      ctx.buf.data[pos+1] = byte((v shr 8) and 0xFF)
      ctx.buf.data[pos+2] = byte((v shr 16) and 0xFF)
      ctx.buf.data[pos+3] = byte((v shr 24) and 0xFF)

  # Drop them HIGHEST position first: a removal only rebases positions after
  # itself, so the lower ones stay valid as we go.
  if deadFrameAdjusts.len > 0:
    deadFrameAdjusts.sort(Descending)
    for pos in deadFrameAdjusts:
      ctx.buf.data.removeRange(pos, 4)
      shiftCodePositions(ctx, pos + 4, -4)

  # Close this proc's debug-info record. The frame `sub`'s CFA delta is exactly
  # the immediate just patched into it, which is why the FDE could not be
  # finished at the instruction itself.
  if ctx.unwind.len > 0 and ctx.unwind[^1].stop < 0:
    var carry = 0'i32
    for k in 0 ..< ctx.unwind[^1].steps.len:
      if ctx.unwind[^1].steps[k].ssizeSlot:
        carry += int32(alignedStackSize) +
                 int32(if ctx.ssizePatches.len > 0: ctx.ssizePatches[0].pad else: 0)
        ctx.unwind[^1].steps[k].ssizeSlot = false
      ctx.unwind[^1].steps[k].cfaOff += carry
    ctx.unwind[^1].stop = ctx.buf.data.len
  ctx.inPrologue = false

  ctx.scope = oldScope

proc genStmt(n: var Cursor; ctx: var GenContext) =
  if atTag(n, StmtsTagId):
    loopInto n:
      genInst(n, ctx)
  else:
    genInst(n, ctx)

proc parseOperand(n: var Cursor; ctx: var GenContext): Operand =
  if n.kind == TagLit:
    let t = n.tag
    if rawTagIsX64Reg(t):
      result.reg = parseRegister(n)
      result.typ = Type(kind: RegisterT, regBits: 64) # Pure register - accepts any type
      # Check if this register is bound to a variable
      if result.reg in ctx.regBindings and not ctx.lenient:
        error("Register " & $result.reg & " is bound to variable '" &
              ctx.regBindings[result.reg] & "', use the variable name instead", n)
      # R11 is the codegen's RESERVED staging bridge — never a syscall/call argument
      # or a callee-saved home. A *raw* `(reg r11)` therefore always means a value or
      # address was left in the bridge as an UNTRACKED, untyped register; the codegen
      # must hand it out as a typed `(rebind)` binding (see arkham `pickStagingSealed`).
      # Rejecting it here keeps the staging bridge inside the typed-binding model so a
      # dropped/clobbered operand is an assemble-time error, not a runtime miscompile.
      if result.reg == x86.R11 and not ctx.lenient:
        error("raw r11 operand: the staging bridge must be a typed (rebind) binding, " &
              "never a bare (reg) — untracked value/address in the bridge", n)
    elif t == NilTagId:
      # `(nil)` as a value: the null pointer — a 0 immediate typed `nil` (compatible
      # with any pointer, never a sized integer). See `compatible`'s NilT arm.
      result.kind = okImm
      result.immVal = 0
      result.typ = Type(kind: TypeKind.NilT)
      inc n
    elif t == DotTagId:
      # (dot <base-reg> <stackvar> <fieldname>) for stack objects, or
      # (dot <ptr-var> <fieldname>) for pointer variables
      inc n

      var objType: Type
      var baseReg: x86.Register
      var baseDisp: int32 = 0
      var baseIndex: x86.Register
      var baseScale = 1
      var baseHasIndex = false
      var useFsSegment = false
      var fieldName: string

      # Check if first arg is a register (explicit stack addressing)
      if n.kind == TagLit and rawTagIsX64Reg(n.tag):
        # (dot (base-reg) stackvar fieldname) - explicit stack object access
        baseReg = parseRegister(n)

        # Parse stack variable name for offset
        if n.kind != Symbol:
          error("Expected stack variable name in dot expression", n)
        let stackVarName = getSym(n)
        let stackSym = lookupWithAutoImport(ctx, ctx.scope, stackVarName, n)
        if stackSym == nil or not stackSym.typ.isOnStack:
          error("Expected stack variable in dot, got: " & stackVarName, n)
        # Unwrap StackOffT to get the base type
        let baseTyp = if stackSym.typ.kind == StackOffT: stackSym.typ.offType else: stackSym.typ
        if baseTyp.kind notin {TypeKind.ObjectT, TypeKind.UnionT}:
          error("dot requires object/union type, got " & $baseTyp, n)
        baseDisp = int32(stackSym.offset)
        objType = baseTyp
        inc n

        # Parse field name
        if n.kind != Symbol:
          error("Expected field name in dot expression", n)
        fieldName = getSym(n)
        inc n
      else:
        # (dot ptr-var fieldname) - pointer variable access
        var baseOp = parseOperand(n, ctx)

        if n.kind != Symbol:
          error("Expected field name in dot expression", n)
        fieldName = getSym(n)
        inc n

        if baseOp.typ.kind == TypeKind.PtrT:
          # Base is a pointer to an object or union
          objType = resolvedBase(baseOp.typ, ctx, n)
          if objType.kind notin {TypeKind.ObjectT, TypeKind.UnionT}:
            error("Cannot access field of non-object/union type " & $objType, n)
          if baseOp.kind == okMem:
            baseReg = baseOp.mem.base
            baseDisp = baseOp.mem.displacement
            baseHasIndex = baseOp.mem.hasIndex
            baseIndex = baseOp.mem.index
            baseScale = baseOp.mem.scale
            useFsSegment = baseOp.mem.useFsSegment
          else:
            baseReg = baseOp.reg
        else:
          error("dot requires (base-reg stackvar field) or (ptr-var field), got " & $baseOp.typ, n)

      # Find field in object/union type. Offsets are precomputed in
      # parseObjectBody/parseUnionBody — inherited (base) fields carry their base
      # offsets, own fields start at sizeof(base), unions are all 0 — so a plain
      # name lookup yields the right displacement.
      var fieldOffset = 0
      var fieldType: Type = nil
      for (fname, ftype, foff) in objType.fields:
        if fname == fieldName:
          fieldType = ftype
          fieldOffset = foff
          break

      if fieldType == nil:
        error("Field '" & fieldName & "' not found in " & $objType.kind, n)

      # Result is memory operand pointing to the field
      result.kind = okMem
      result.mem = x86.MemoryOperand(
        base: baseReg,
        index: baseIndex,
        scale: baseScale,
        displacement: baseDisp + int32(fieldOffset),
        hasIndex: baseHasIndex,
        useFsSegment: useFsSegment
      )
      result.typ = Type(kind: TypeKind.PtrT, base: fieldType)

    elif t == AtTagId:
      # (at <base-reg> <stackvar> <index>)            stack array, OR
      # (at <aptr-or-ptr-to-array> <index>)           folds to base+index*scale, OR
      # (at <base> <index> <scratch-reg>)             3-operand form: the element
      #   stride isn't a legal SIB scale (a multi-dimensional array's outer
      #   dimension), so arkham hands us a scratch register and WE compute the
      #   address `base + index*stride` into it — keeping the size arithmetic in
      #   the typed layer (we know the stride) and the register allocation in
      #   arkham (it owns the scratch). `into` bounds the node so the optional
      #   third operand is read without running into the following sibling.
      into n:
        var elemType: Type
        var baseReg: x86.Register
        var baseDisp: int32 = 0
        var baseIndex: x86.Register
        var baseScale: int = 0
        var baseHasIndex = false
        var indexOp: Operand

        if n.kind == TagLit and rawTagIsX64Reg(n.tag):
          # (at (base-reg) stackvar index) - explicit stack array access
          baseReg = parseRegister(n)
          if n.kind != Symbol:
            error("Expected stack variable name in at expression", n)
          let stackVarName = getSym(n)
          let stackSym = lookupWithAutoImport(ctx, ctx.scope, stackVarName, n)
          if stackSym == nil or not stackSym.typ.isOnStack:
            error("Expected stack variable in at, got: " & stackVarName, n)
          let baseTyp = if stackSym.typ.kind == StackOffT: stackSym.typ.offType else: stackSym.typ
          if baseTyp.kind != TypeKind.ArrayT:
            error("at requires array type, got " & $baseTyp, n)
          baseDisp = int32(stackSym.offset)
          elemType = baseTyp.elem
          inc n
          indexOp = parseOperand(n, ctx)
        else:
          # (at <base> index) where <base> is an array-pointer variable (`aptr`) or
          # a pointer-to-array address `(cast (ptr (array elem N)) base)` — how
          # arkham reaches a global array or a deref'd array field. A nested `(at …)`
          # base carries its own base register + displacement (+ index), folded on.
          var baseOp = parseOperand(n, ctx)
          indexOp = parseOperand(n, ctx)
          if baseOp.typ.kind == TypeKind.AptrT:
            elemType = resolvedBase(baseOp.typ, ctx, n)
            baseReg = baseOp.reg
          elif baseOp.typ.kind == TypeKind.PtrT and
               resolvedBase(baseOp.typ, ctx, n).kind == TypeKind.ArrayT:
            elemType = resolvedBase(baseOp.typ, ctx, n).elem
            if baseOp.kind == okMem:
              baseReg = baseOp.mem.base
              baseDisp = baseOp.mem.displacement
              baseIndex = baseOp.mem.index
              baseScale = baseOp.mem.scale
              baseHasIndex = baseOp.mem.hasIndex
            else:
              baseReg = baseOp.reg
          else:
            error("at requires (base-reg stackvar index) or a pointer-to-array base, got " & $baseOp.typ, n)

        if not isIntegerType(indexOp.typ):
          error("Array index must be integer type, got " & $indexOp.typ, n)

        # Optional third operand: an arkham-supplied scratch register for a stride
        # that can't be a SIB scale.
        var hasScratch = false
        var scratchReg: x86.Register
        if n.hasMore and n.kind == TagLit and rawTagIsX64Reg(n.tag):
          scratchReg = parseRegister(n)
          hasScratch = true
        elif n.hasMore and n.kind == Symbol:
          # arkham may pass the scratch as a `rebind`-bound temp name rather than a
          # raw `(reg)`; resolve it to its register (a raw `(reg)` for a bound reg is
          # itself rejected elsewhere, so the name is the only legal spelling).
          let scratchOp = parseOperand(n, ctx)
          if scratchOp.kind != okReg:
            error("at: scratch operand must be a register", n)
          scratchReg = scratchOp.reg
          hasScratch = true

        if hasScratch:
          # Compute `scratch = baseAddr + index*stride` ourselves (stride from the
          # element type). arkham only emits this for a register index, so indexOp
          # is in a register. base+disp (and a power-of-two-free stride) collapse via
          # one `imul` + one `lea`; a base that already holds an index would need a
          # second index slot we don't have (a deeper mixed-stride nest — not emitted
          # by the current arkham).
          if indexOp.kind != okReg:
            error("at: 3-operand form expects a register index", n)
          if baseHasIndex:
            error("at: 3-operand form cannot extend a base that already has an index", n)
          # Disjointness: the stride scratch must not alias the base register. The
          # `mov scratch,index` below clobbers `scratch` before the `lea` reads `base`,
          # so `scratch==base` silently drops the base (→ a wild address). This is the
          # arkham allocation bug class ("Bug J") that used to surface only as an
          # ASLR-only runtime segfault; flag it at assemble time. `scratch==index` is
          # fine (the mov is then a no-op) and is intentionally allowed (under register
          # pressure it can be the only free choice).
          if scratchReg == baseReg:
            error("at: 3-operand stride scratch aliases the base register (" &
                  $baseReg & ") — the base is clobbered before use (codegen bug)", n)
          let stride = asmSizeOf(elemType)
          # `base + index*stride` without a multiply wherever the stride allows it.
          # A SIB scale covers {1,2,4,8}; a SUM of two scales covers the strides that
          # actually dominate this compiler — 16 (`HashEntry`, and any pair of words)
          # is 8+8, so two `lea`s replace `mov`+`imul`+`lea`: one instruction fewer,
          # and no 3-cycle `imul` on the address path of every indexed access.
          #
          # The split form reads `index` TWICE, so it needs `scratch != index` —
          # which the disjointness rule above deliberately permits (under pressure
          # arkham may hand us the index register as the scratch). When they alias,
          # the first `lea` would destroy the index before the second reads it, so
          # fall through to the sequential form, where `mov scratch, index` is a
          # no-op and the shift/multiply operates in place.
          var loScale = 0
          var hiScale = 0
          if scratchReg != indexOp.reg:
            if stride in [1, 2, 4, 8]:
              loScale = stride                       # a single `lea` does it all
            else:
              for a in [8, 4, 2, 1]:
                if stride > a and (stride - a) in [1, 2, 4, 8]:
                  loScale = a; hiScale = stride - a; break
          if loScale != 0:
            x86.emitLea(ctx.buf.data, scratchReg,                   # scratch = base + disp + index*lo
              x86.MemoryOperand(base: baseReg, index: indexOp.reg, scale: loScale,
                                displacement: baseDisp, hasIndex: true))
            if hiScale != 0:
              x86.emitLea(ctx.buf.data, scratchReg,                 # scratch += index*hi
                x86.MemoryOperand(base: scratchReg, index: indexOp.reg, scale: hiScale,
                                  displacement: 0, hasIndex: true))
          else:
            x86.emitMov(ctx.buf.data, scratchReg, indexOp.reg)      # scratch = index
            if stride > 0 and (stride and (stride - 1)) == 0:
              var sh = 0
              while (1 shl sh) < stride: inc sh
              x86.emitShl(ctx.buf.data, scratchReg, sh)             # scratch <<= log2(stride)
            else:
              x86.emitImulImm(ctx.buf.data, scratchReg, int32(stride))
            x86.emitLea(ctx.buf.data, scratchReg,                   # scratch = base + disp + scratch
              x86.MemoryOperand(base: baseReg, index: scratchReg, scale: 1,
                                displacement: baseDisp, hasIndex: true))
          result.kind = okMem
          result.mem = x86.MemoryOperand(base: scratchReg, displacement: 0, hasIndex: false)
        elif indexOp.kind == okImm:
          # Immediate index: fold into the displacement (any stride).
          let offset = indexOp.immVal * asmSizeOf(elemType)
          result.kind = okMem
          result.mem = x86.MemoryOperand(
            base: baseReg, index: baseIndex, scale: baseScale,
            displacement: baseDisp + int32(offset), hasIndex: baseHasIndex)
        elif indexOp.kind == okMem:
          error("Array index cannot be memory operand", n)
        else:
          # Register index folded as a SIB scale. arkham only emits the 2-operand
          # form when the stride is a legal scale and the base has no index, so these
          # are invariants here (kept as asserts).
          if baseHasIndex:
            error("at: two register indices cannot fold into one memory operand", n)
          # Disjointness: in the folded SIB `[base + index*scale]`, base and index are
          # two distinct live values (an array address and an element index); aliasing
          # them computes `base + base*scale` (a codegen bug). Flag it rather than emit
          # a silently-wrong address.
          if indexOp.reg == baseReg:
            error("at: array base and index occupy the same register (" &
                  $baseReg & ") — distinct values aliased (codegen bug)", n)
          let elemSize = asmSizeOf(elemType)
          if elemSize notin [1, 2, 4, 8]:
            error("Element size " & $elemSize & " not a SIB scale and no scratch supplied", n)
          result.kind = okMem
          result.mem = x86.MemoryOperand(
            base: baseReg, index: indexOp.reg, scale: elemSize,
            displacement: baseDisp, hasIndex: true)

        result.typ = Type(kind: TypeKind.PtrT, base: elemType)
        while n.hasMore: skip n

    elif t == LabTagId:
      inc n
      if n.kind != Symbol: error("Expected label usage", n)
      let name = getSym(n)
      let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
      if sym == nil or sym.kind != skLabel: error("Unknown label: " & name, n)
      if sym == ctx.traceSym: ctx.traceUsed = true   # emit the table (appendTraceTable)
      inc n
      result.reg = RAX
      result.label = LabelId(sym.offset)
      # Label address type is pointer to code?
      result.typ = Type(kind: UIntT, bits: 64) # Address
    elif t == CastTagId:
      inc n
      let castType = parseType(n, ctx.scope, ctx)
      # Cast allows us to opt-out of type system, so we don't check against expectedType here
      var op = parseOperand(n, ctx)
      op.typ = castType
      # An explicit sub-width int cast over a REGISTER is a width annotation:
      # the ALU family operates on the low `castBits` of the register (32-bit
      # zero-extends the destination, 8/16 preserve its upper bits, flags at
      # that width). Recorded only here — a symbol's declared sub-width type
      # never sizes a register operation, so existing output is byte-identical.
      if op.kind == okReg and castType != nil and
         castType.kind in {IntT, UIntT} and castType.bits in [8, 16, 32]:
        op.castBits = castType.bits
      else:
        op.castBits = 0
      result = op
    elif t == MemTagId:
      # (mem <address-expr>) or (mem <base> <offset>) or (mem <base> <index> <scale>) etc.
      # `into` bounds the cursor to the mem node, so the OPTIONAL index/scale/offset
      # checks below are gated by `hasMore` and never read into the following sibling
      # (there is no ParRi sentinel to stop them otherwise).
      into n:
        # Check if first child is an address expression (dot/at) or explicit addressing
        if n.kind == TagLit and (n.tag == DotTagId or n.tag == AtTagId):
          # Wrapped address expression: (mem (dot ...) or (mem (at ...))
          var addrOp = parseOperand(n, ctx)
          if addrOp.kind != okMem:
            error("mem requires address expression", n)

          # Dereference the pointer type
          if addrOp.typ.kind != TypeKind.PtrT:
            error("mem requires pointer type, got " & $addrOp.typ, n)

          result = addrOp
          result.typ = resolvedBase(addrOp.typ, ctx, n)  # Dereference: ptr T -> T
        elif n.kind == IntLit and getInt(n) == 0:
          # `(mem 0 index scale [disp])` — the NO-BASE scaled form
          # `[index*scale + disp]` (SIB base=101). The literal 0 base is
          # unambiguous: a plain base is never an immediate. This is how a pure
          # scaled index (`lea D, [S*8]`, gcc's `[rax*4+0]`) is spelled.
          inc n
          var indexReg: x86.Register
          if n.kind == TagLit and rawTagIsX64Reg(n.tag):
            let idxOp = parseOperand(n, ctx)   # keeps the binding guards
            indexReg = idxOp.reg
          elif n.kind == Symbol:
            let indexName = getSym(n)
            let indexSym = lookupWithAutoImport(ctx, ctx.scope, indexName, n)
            if indexSym != nil and indexSym.kind in {skVar, skParam} and
               indexSym.reg != InvalidTagId:
              indexReg = tagToRegister(indexSym.reg, n)
              inc n
            else:
              error("Expected register index in no-base mem", n)
          else:
            error("Expected register index in no-base mem", n)
          if not (n.hasMore and n.kind == IntLit):
            error("no-base mem requires an explicit scale", n)
          let scale0 = int(getInt(n))
          if scale0 notin [1, 2, 4, 8]:
            error("mem scale must be 1, 2, 4, or 8", n)
          inc n
          var disp0: int32 = 0
          if n.hasMore and n.kind == IntLit:
            disp0 = int32(getInt(n))
            inc n
          result.kind = okMem
          result.mem = x86.MemoryOperand(
            base: x86.RAX,          # unused; RAX keeps REX.B-from-base silent
            index: indexReg,
            scale: scale0,
            displacement: disp0,
            hasIndex: true,
            noBase: true
          )
          result.typ = Type(kind: IntT, bits: 64)
        else:
          # Explicit addressing: (mem base) or (mem base offset) or (mem base index scale [offset])
          var baseOp = parseOperand(n, ctx)
          if baseOp.kind == okImm or baseOp.kind == okMem:
            error("mem base must be a register", n)

          var displacement: int32 = 0
          var hasIndex = false
          var indexReg: x86.Register = x86.RAX
          var scale: int = 1

          # Check for an optional offset/index (present only if the mem node has
          # more children).
          var stackVarType: Type = nil
          if n.hasMore and n.kind == TagLit and n.tag == ArgTagId:
            # (mem (rsp) (arg name)) — an outgoing stack-argument slot. The arg's
            # byte offset within the reserved area becomes the displacement.
            var an = n; inc an                  # peek the arg name before consuming
            let argName = if an.kind == Symbol: getSymId(an) else: SymId(0)
            let argOff = parseOperand(n, ctx)
            if argOff.kind != okImm:
              error("(arg ...) in mem must denote a stack argument", n)
            displacement = int32(argOff.immVal)
            if argName != SymId(0): ctx.callContext.argsSet.incl argName
            # The slot IS the parameter, so it carries the parameter's declared type —
            # not the machine word a bare `(rsp)` base would otherwise imply. Without
            # this, storing e.g. a `nil` into a stack-passed `pointer` parameter is a
            # type error against a phantom `(i 64)`. An AGGREGATE keeps the word type:
            # `(arg pN k)` addresses one eightbyte of it, not the whole object.
            if argOff.typ != nil:
              let pt = if argOff.typ.kind == StackOffT: argOff.typ.offType else: argOff.typ
              if pt != nil and pt.kind notin {TypeKind.ObjectT, TypeKind.ArrayT, TypeKind.UnionT}:
                stackVarType = pt
          elif n.hasMore and n.kind == TagLit and rawTagIsX64Reg(n.tag):
            # `(mem <base> <index-reg> [scale [disp]])` with a raw register index —
            # the general SIB form `[base + index*scale + disp]`. Parsing the index
            # through parseOperand keeps the binding guards (a bound register must be
            # named, r11 stays a typed binding). Base==index is legal here: unlike
            # `(at)`, this form makes no claim that the two are distinct values — it
            # IS the encoding, as a distilled gcc body may spell it.
            let idxOp = parseOperand(n, ctx)
            hasIndex = true
            indexReg = idxOp.reg
            if n.hasMore and n.kind == IntLit:
              scale = int(getInt(n))
              if scale notin [1, 2, 4, 8]:
                error("mem scale must be 1, 2, 4, or 8", n)
              inc n
              if n.hasMore and n.kind == IntLit:
                displacement = int32(getInt(n))
                inc n
          elif n.hasMore and (n.kind == IntLit or n.kind == Symbol):
            if n.kind == IntLit:
              displacement = int32(getInt(n))
              inc n
            elif n.kind == Symbol:
              # Could be index register or stack variable (used as offset)
              let indexName = getSym(n)
              let indexSym = lookupWithAutoImport(ctx, ctx.scope, indexName, n)
              if indexSym != nil and (indexSym.kind == skVar or indexSym.kind == skParam) and indexSym.typ.isOnStack:
                # Stack variable - use its offset as displacement and preserve type (unwrap StackOffT)
                displacement = int32(indexSym.offset)
                stackVarType = if indexSym.typ.kind == StackOffT: indexSym.typ.offType else: indexSym.typ
                inc n
                if n.hasMore and n.kind == IntLit:
                  # `(mem <base> <stackvar> <disp>)` — a raw byte offset WITHIN the named
                  # slot, folded into the slot's own displacement. This is what lets a
                  # word of a stack aggregate be read/written without first materializing
                  # the aggregate's address in a register: a copy out of a named slot then
                  # costs zero address registers instead of one. The access WIDTH still
                  # comes from the operand's type, so a caller reading a raw eightbyte
                  # wraps this in `(cast (u 64) …)`.
                  #
                  # Bounds-checked against the slot — the one safety a `(cast (aptr T)
                  # <reg>)` access can never have, since the register form has no
                  # object to check against.
                  let extra = getInt(n)
                  let slotSize = asmSizeOf(indexSym.typ)
                  if extra < 0 or extra >= slotSize:
                    error("offset " & $extra & " is outside stack slot '" & indexName &
                          "' (" & $slotSize & " bytes)", n)
                  displacement += int32(extra)
                  inc n
              elif indexSym != nil and indexSym.kind in {skVar, skParam} and
                   indexSym.reg != InvalidTagId:
                # This is the index register (a register-homed local or param —
                # the same {skVar, skParam} convention as every operand path)
                hasIndex = true
                indexReg = tagToRegister(indexSym.reg, n)
                inc n

                # Check for scale
                if n.hasMore and n.kind == IntLit:
                  scale = int(getInt(n))
                  if scale notin [1, 2, 4, 8]:
                    error("mem scale must be 1, 2, 4, or 8", n)
                  inc n

                  # Check for displacement after scale
                  if n.hasMore and n.kind == IntLit:
                    displacement = int32(getInt(n))
                    inc n
              else:
                error("Expected index register or stack variable in mem", n)

          result.kind = okMem
          result.mem = x86.MemoryOperand(
            base: baseOp.reg,
            index: indexReg,
            scale: scale,
            displacement: displacement,
            hasIndex: hasIndex
          )
          # The deref of `(ptr T)` has type T — no special cases (a stack var contributes
          # its own type). `memWidthOpc`/`intMemAccess` size it from T (a sub-word int/bool
          # → a narrow movzx/movsx, e.g. the SSO `(ptr (u 8))` slen byte; everything ≥8
          # bytes → a word); `movCompatible` decides whether T can move to/from the chosen
          # register. A bare register base (no pointer type) is a plain machine word.
          if stackVarType != nil:
            result.typ = stackVarType
          elif baseOp.typ != nil and baseOp.typ.kind in {TypeKind.PtrT, TypeKind.AptrT}:
            result.typ = resolvedBase(baseOp.typ, ctx, n)
          else:
            result.typ = Type(kind: IntT, bits: 64)
    elif t == SsizeTagId:
      # `(ssize)` is the frame size, filled in at `finalize` once every `(s)` slot is
      # allocated. The optional `(ssize N)` adds N bytes to THIS site only — the
      # prologue/epilogue use it to fold the 16-byte alignment pad into the frame
      # adjustment instead of emitting a second `sub rsp, 8` / `add rsp, 8`.
      result.kind = okSsize
      result.typ = Type(kind: IntT, bits: 64)
      result.immVal = 0
      inc n
      if n.kind == IntLit:
        result.immVal = n.intVal
        inc n
    elif t == CsizeTagId:
      # (csize) - call stack argument size
      if not ctx.inCall:
        error("(csize) can only be used inside a prepare block", n)
      result.kind = okCsize
      result.immVal = int64(ctx.callContext.stackArgSize)
      result.typ = Type(kind: IntT, bits: 64)
      inc n
    elif t == ArgTagId:
      # (arg name [k]) - argument reference in prepare block. Capture the node cursor
      # for diagnostics that run after we've advanced past it. `into` bounds the cursor
      # to the arg's children so the optional word index `k` is read without leaking the
      # following sibling.
      let argTok = n
      if not ctx.inCall:
        error("(arg ...) can only be used inside a prepare block", argTok)
      var argName = SymId(0)
      var wordIdx = 0          # selects the k-th register of a ≤16B by-value aggregate arg
      into n:
        if n.kind != Symbol: error("Expected argument name in (arg ...)", n)
        argName = getSymId(n)
        inc n
        if n.hasMore and n.kind == IntLit:
          wordIdx = int(getInt(n))
          inc n

      let paramPtr = findParam(ctx.callContext.typ, argName)
      if paramPtr == nil:
        error("Unknown argument: " & ctx.nameOf(argName), argTok)

      if paramPtr.typ.isOnStack:
        # Stack argument - return its byte offset as an immediate. The base offset is
        # the running byte position among the stack-passed params; the optional word
        # index `k` selects the k-th eightbyte of a multi-word stack aggregate (each
        # word is 8 bytes), so a by-value struct that spilled to the stack can be
        # marshalled/read one word at a time the same way a register-passed one is.
        var offset = ctx.callContext.stackArgBase   # Win64 extern: above the shadow space
        for p in ctx.callContext.typ.params:
          if p.typ.isOnStack:
            if p.name == argName:
              break
            offset += slots.alignedSize(p.typ)
        result.kind = okImm
        result.argName = argName
        result.immVal = int64(offset + wordIdx * asmWordSize())
        result.typ = paramPtr.typ
      else:
        # Register argument - return the (word-`wordIdx`) register
        if wordIdx >= paramPtr.regs.len:
          error("argument word index out of range for " & ctx.nameOf(argName), argTok)
        result.kind = okArg
        result.argName = argName
        result.reg = tagToRegister(paramPtr.regs[wordIdx], argTok)
        result.typ =
          if paramPtr.typ.kind in {TypeKind.ObjectT, TypeKind.ArrayT, TypeKind.UnionT}: Type(kind: RegisterT, regBits: 64)
          else: paramPtr.typ
    elif t == ResTagId:
      # (res name) - result reference in prepare block (after call). Capture the
      # node cursor for diagnostics: the semantic checks below run after we've
      # advanced past the node, where `n` would sit at the scope end (no loadable
      # token under nifcore).
      let resTok = n
      if not ctx.inCall:
        error("(res ...) can only be used inside a prepare block", resTok)
      inc n
      if n.kind != Symbol: error("Expected result name in (res ...)", n)
      let resName = getSymId(n)
      inc n

      if not ctx.callContext.callEmitted:
        error("(res ...) can only be used after (call) or (extcall)", resTok)
      let resPtr = findResult(ctx.callContext.typ, resName)
      if resPtr == nil:
        error("Unknown result: " & ctx.nameOf(resName), resTok)
      if resName in ctx.callContext.resultsSet:
        error("Result already bound: " & ctx.nameOf(resName), resTok)
      ctx.callContext.resultsSet.incl(resName)

      result.reg = tagToRegister(resPtr.reg, resTok)
      result.typ = resPtr.typ
    else:
      error("Unexpected operand tag: " & $t, n)
  elif n.kind == IntLit:
    result.kind = okImm
    result.immVal = getInt(n)
    result.typ = Type(kind: IntLitT, bits: 64, litVal: result.immVal)
    inc n
  elif n.kind == Symbol:
    let name = getSym(n)
    let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
    if sym != nil and (sym.kind == skVar or sym.kind == skParam):
      if sym.typ.isOnStack:
        # Return StackOffT - operations like `add` will reject this at type check
        result.kind = okMem
        result.mem = x86.MemoryOperand(base: x86.RSP, displacement: int32(sym.offset))
        result.typ = sym.typ  # Already StackOffT from declaration
        inc n
        return
      elif sym.reg != InvalidTagId:
        result.reg = tagToRegister(sym.reg, n)

        # Check if clobbered
        if result.reg in ctx.clobbered and not ctx.lenient:
          error("Access to variable '" & name & "' in register " & $result.reg & " which was clobbered", n)

      result.typ = sym.typ
      inc n
    elif sym != nil and sym.kind == skLabel:
      result.kind = okLabel
      result.label = LabelId(sym.offset)
      result.typ = Type(kind: UIntT, bits: 64)
      inc n
    elif sym != nil and sym.kind == skRodata:
      result.kind = okLabel
      if sym.offset == -1:
        # Forward reference - create label now but don't define it yet
        # It will be defined when the rodata is actually written
        let labId = ctx.buf.createLabel()
        sym.offset = int(labId)
        result.label = labId
      else:
        result.label = LabelId(sym.offset)
      result.typ = Type(kind: UIntT, bits: 64) # Address of rodata
      inc n
    elif sym != nil and sym.kind == skGvar:
      # Global variable - return its address. A foreign global is bundled into
      # this same image (see generateSymbol) and accessed like a local one.
      result.kind = okLabel
      if sym.offset == -1:
        # Forward reference - create label now
        let labId = ctx.buf.createLabel()
        sym.offset = int(labId)
        result.label = labId
      else:
        result.label = LabelId(sym.offset)
      result.gvarSym = sym                       # carry the symbol so `lea` can patch
      result.typ = Type(kind: UIntT, bits: 64) # Address of gvar
      inc n
    elif sym != nil and sym.kind == skTvar:
      # Accessing thread local variable via FS segment
      # On x86-64 Linux, TLS variables are accessed via FS segment
      # The offset is stored in sym.offset (allocated in pass2)
      # Use RBP as base register (standard for offset-only addressing)
      result.kind = okMem
      result.mem = x86.MemoryOperand(
        base: x86.RBP,  # RBP allows displacement-only addressing
        displacement: int32(sym.offset),
        hasIndex: false,
        useFsSegment: true  # Use FS segment register
      )
      result.typ = sym.typ
      inc n
    elif sym != nil and sym.kind == skProc:
      # A proc used as a value → its code address (RIP-relative): `lea reg, proc`
      # materializes a function pointer. Same label the proc's definition / a
      # direct `(call)` binds, so it resolves to the proc's entry.
      result.kind = okLabel
      if sym.offset == -1:
        let labId = ctx.buf.createLabel()
        sym.offset = int(labId)
        result.label = labId
      else:
        result.label = LabelId(sym.offset)
      result.typ = Type(kind: UIntT, bits: 64)   # a code pointer
      inc n
    else:
      error("Unknown or invalid symbol: " & name, n)
  else:
    error("Unexpected operand kind", n)

proc parseDest(n: var Cursor; ctx: var GenContext;
               allowWidthCast = false): Operand =
  if n.kind == TagLit and rawTagIsX64Reg(n.tag):
    result.reg = parseRegister(n)
    result.typ = Type(kind: RegisterT, regBits: 64)
    # Check if this register is bound to a variable
    if result.reg in ctx.regBindings and not ctx.lenient:
      error("Register " & $result.reg & " is bound to variable '" &
            ctx.regBindings[result.reg] & "', use the variable name instead", n)
    if result.reg == x86.R11 and not ctx.lenient:   # the reserved staging bridge
      error("raw r11 destination: the staging bridge must be a typed (rebind) binding, " &
            "never a bare (reg)", n)
  elif n.kind == TagLit and n.tag == ArgTagId:
    # (arg name [k]) as destination - for register arguments in prepare block. `into`
    # bounds the cursor to the arg's own children so the optional word index `k` is read
    # without leaking the following sibling (the `(mov)` source) into the check.
    if not ctx.inCall:
      error("(arg ...) can only be used inside a prepare block", n)
    var argName = SymId(0)
    var wordIdx = 0                      # selects the k-th register of a ≤16B aggregate arg
    into n:
      if n.kind != Symbol: error("Expected argument name in (arg ...)", n)
      argName = getSymId(n)
      inc n
      if n.hasMore and n.kind == IntLit:
        wordIdx = int(getInt(n))
        inc n

    let paramPtr = findParam(ctx.callContext.typ, argName)
    if paramPtr == nil:
      error("Unknown argument: " & ctx.nameOf(argName), n)

    if paramPtr.typ.isOnStack:
      error("Stack argument '" & ctx.nameOf(argName) & "' cannot be used directly as destination, use (mem (rsp) (arg " & ctx.nameOf(argName) & "))", n)

    # Track that this argument is being set. A multi-word aggregate fills several words
    # under the same name; count it once (on word 0) so the missing-arg check passes,
    # but allow the later words without a "already set" error.
    if wordIdx == 0:
      if argName in ctx.callContext.argsSet:
        error("Argument already set: " & ctx.nameOf(argName), n)
      ctx.callContext.argsSet.incl(argName)

    # Return the (word-`wordIdx`) register for this argument
    if wordIdx >= paramPtr.regs.len:
      error("argument word index out of range for " & ctx.nameOf(argName), n)
    result.kind = okArg
    result.argName = argName
    result.reg = tagToRegister(paramPtr.regs[wordIdx], n)
    # A by-value aggregate spread over registers receives a raw 64-bit word per slot,
    # not the whole aggregate — type it as a register so the word `(mov)` type-checks.
    result.typ =
      if paramPtr.typ.kind in {TypeKind.ObjectT, TypeKind.ArrayT, TypeKind.UnionT}: Type(kind: RegisterT, regBits: 64)
      else: paramPtr.typ
  elif n.kind == TagLit and (n.tag == MemTagId or n.tag == DotTagId or n.tag == AtTagId or
                             n.tag == CastTagId):
    # `(cast T <mem>)` is a legal destination: a cast only retypes an operand, and a
    # memory operand is a legal destination, so retyping one is too. This is how a raw
    # eightbyte is STORED into a named stack slot at an offset — `(cast (u 64) (mem (rsp)
    # v 8))` — where the slot's own declared (aggregate) type would otherwise size the
    # access. `okMem` is still required, so `(cast T (reg))` remains rejected: a register
    # destination must be a typed binding, never a retyped raw register.
    #
    # ONE exception, and only where the instruction opts in (`allowWidthCast` —
    # the ALU family, never `mov`): an explicit SUB-WIDTH int cast over a
    # register destination is a width annotation on the operation, not a
    # retyping — `(add (cast (u 32) (rax)) …)` is a 32-bit add. A 64-bit cast
    # stays rejected everywhere (that is the escape hatch this guard exists
    # for), and `mov` keeps the strict rule so the pointer-store protection
    # cannot be casted away.
    let op = parseOperand(n, ctx)
    if op.kind != okMem and not (allowWidthCast and op.kind == okReg and
                                 op.castBits != 0):
      error("Expected memory destination", n)
    result = op
  elif n.kind == Symbol:
    let name = getSym(n)
    let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
    # A param (skParam) is bound to a register / stack slot exactly like a var, so
    # it is a valid destination too (mirrors parseDestA64 and the source paths).
    if sym != nil and (sym.kind == skVar or sym.kind == skParam):
       if sym.typ.isOnStack:
         # Return StackOffT - operations like `add` will reject this at type check
         result.kind = okMem
         result.mem = x86.MemoryOperand(base: x86.RSP, displacement: int32(sym.offset))
         result.typ = sym.typ  # Already StackOffT from declaration
         inc n
         return
       elif sym.reg != InvalidTagId:
         result.reg = tagToRegister(sym.reg, n)
         result.typ = sym.typ
         # Writing to a register makes it valid (unclobbered)
         ctx.clobbered.excl(result.reg)
       else:
         error("Variable has no location", n)
       inc n
    elif sym != nil and sym.kind == skTvar:
       # Writing to thread local variable via FS segment
       result.kind = okMem
       result.mem = x86.MemoryOperand(
         base: RBP,  # RBP allows displacement-only addressing
         displacement: int32(sym.offset),
         hasIndex: false,
         useFsSegment: true  # Use FS segment register
       )
       result.typ = sym.typ
       inc n
    else:
       error("Expected variable or register as destination", n)
  else:
    error("Expected destination", n)

proc checkType(want, got: Type; n: Cursor) =
  if gLenient: return
  if not compatible(want, got):
    typeError(want, got, n)

proc checkIntegerArithmetic(t: Type; op: string; n: Cursor) =
  if gLenient: return
  if not canDoIntegerArithmetic(t):
    # NOT "integer or pointer": `canDoIntegerArithmetic` admits no pointer of any
    # kind, and saying otherwise sends the reader looking for which pointer was
    # meant. Name the two legal spellings instead — that is what the producer has
    # to change to.
    error("Operation '" & op & "' requires an integer type, got " & $t &
          " — Leng has no arithmetic on pointers: offset an array pointer with " &
          "`(at …)`/`(pat …)`, or cast to an integer, compute, and cast back", n)

proc checkComparable(t: Type; op: string; n: Cursor) =
  if gLenient: return
  if not canCompare(t):
    error("Operation '" & op & "' requires a comparable type, got " & $t, n)

proc checkIntegerType(t: Type; op: string; n: Cursor) =
  if gLenient: return
  if not isIntegerType(t):
    error("Operation '" & op & "' requires integer type, got " & $t, n)

proc checkExchangeType(t: Type; op: string; n: Cursor) =
  if not canExchange(t):
    error("Operation '" & op & "' requires an integer or pointer type, got " & $t, n)

proc checkFloatType(t: Type; op: string; n: Cursor) =
  if not isFloatType(t):
    error("Operation '" & op & "' requires floating point type, got " & $t, n)

proc isXmmOperand(n: Cursor; ctx: GenContext): bool =
  ## True if `n` denotes an xmm register operand — a raw `(xmmN)` tag or a `Symbol`
  ## naming a float local bound to an xmm register. The float instruction handlers
  ## dispatch on this (reg form vs memory form / movfq direction) so a bound float
  ## local, emitted as its name, is recognized as a register operand.
  if isXmmTag(n): return true
  if n.kind == Symbol:
    let sym = ctx.scope.lookup(getSymId(n))   # float locals are never foreign
    result = sym != nil and sym.reg != InvalidTagId and isXmmTagEnum(sym.reg)

proc parseXmmOperand(n: var Cursor; ctx: var GenContext): x86.XmmRegister =
  ## Parse an SSE register *operand* in a scalar-float instruction. The SIMD twin
  ## of `parseOperand`'s register arm: a raw `(xmmN)` tag is accepted only if the
  ## register is not bound (a bound register must be named, so the binding checker
  ## sees the use); a `Symbol` is resolved to the xmm register its float local is
  ## bound to. This is how a raw use of a value still live in a bound xmm register
  ## becomes a build error instead of a silent clobber.
  if isXmmTag(n):
    result = tagToXmm(n.tag)
    if result in ctx.xmmBindings:
      error("Register " & $result & " is bound to variable '" &
            ctx.xmmBindings[result] & "', use the variable name instead", n)
    inc n
  elif n.kind == Symbol:
    let sym = lookupWithAutoImport(ctx, ctx.scope, getSym(n), n)
    if sym == nil:
      error("Unknown symbol: " & getSym(n), n)
    if sym.reg == InvalidTagId or not isXmmTagEnum(sym.reg):
      error("Expected float register variable, got: " & getSym(n), n)
    result = tagToXmm(sym.reg)
    inc n
  else:
    error("expected xmm register or float variable", n)

proc checkBitwiseType(t: Type; op: string; n: Cursor) =
  if gLenient: return
  if not canDoBitwiseOps(t):
    error("Operation '" & op & "' requires integer type, got " & $t, n)

proc checkCompatibleTypes(t1, t2: Type; op: string; n: Cursor) =
  ## Check that two operands have compatible types for an operation
  if not compatible(t1, t2):
    error("Operation '" & op & "' requires compatible types, got " & $t1 & " and " & $t2, n)

proc checkCmpCompatible(t1, t2: Type; n: Cursor) =
  if gLenient: return
  ## Compatibility rule for `cmp` — looser than arithmetic. Two SIZED integers of
  ## ANY width/signedness compare fine (x86 `cmp` runs at register width; a `u32`
  ## value vs an `i64` constant is a perfectly valid comparison — arkham computes
  ## integers in 64-bit registers). Pointers stay strict (governed by `compatible`:
  ## ptr-vs-ptr or ptr-vs-literal only), so an int-vs-pointer mixup is still caught.
  if compatible(t1, t2): return
  const intish = {TypeKind.IntT, TypeKind.UIntT, TypeKind.IntLitT, TypeKind.BoolT}
  if t1.kind in intish and t2.kind in intish: return
  error("Operation 'cmp' requires compatible types, got " & $t1 & " and " & $t2, n)

proc checkBitwiseCompatible(t1, t2: Type; op: string; n: Cursor) =
  if gLenient: return
  ## Compatibility rule for `and`/`or`/`xor` — looser than arithmetic, like `cmp`. Two
  ## SIZED integers of ANY width/signedness combine fine: bitwise ops run at register
  ## width on both x86 and AArch64, and arkham canonicalizes integers in 64-bit
  ## registers, so e.g. `i64 and u32` is valid. It emits exactly that for a widening
  ## `conv` over a narrow bitwise expression: the operation runs in the (already
  ## 64-bit-bound) destination register and a following `lsl`/`asr` pair re-extends.
  ## Non-integer kinds (pointers) stay strict via `compatible`.
  if compatible(t1, t2): return
  const intish = {TypeKind.IntT, TypeKind.UIntT, TypeKind.IntLitT, TypeKind.BoolT}
  if t1.kind in intish and t2.kind in intish: return
  error("Operation '" & op & "' requires compatible types, got " & $t1 & " and " & $t2, n)

proc checkArithCompatible(t1, t2: Type; op: string; n: Cursor) =
  if gLenient: return
  ## Compatibility rule for `add`/`sub` — same as `cmp`/bitwise, on x86 and AArch64
  ## alike: two SIZED integers of ANY width/signedness add fine, because arkham
  ## canonicalizes every integer into a full 64-bit register (a narrow load is
  ## zero/sign-extended), so the op runs at register width and `i64 + u32` (e.g. an
  ## `int` index plus a `uint32` hash) is valid.
  ## A pointer keeps the strict `compatible` rule (ptr+int is handled by callers that
  ## permit it), so an int-vs-pointer mixup is still caught.
  if compatible(t1, t2): return
  const intish = {TypeKind.IntT, TypeKind.UIntT, TypeKind.IntLitT, TypeKind.BoolT}
  if t1.kind in intish and t2.kind in intish: return
  error("Operation '" & op & "' requires compatible types, got " & $t1 & " and " & $t2, n)

proc genPrepareX64(n: var Cursor; ctx: var GenContext) =
  ## Handle (prepare target ... (call) ...) or (prepare target ... (extcall) ...)
  ## The prepare block sets up a call context for type checking and argument tracking.
  var hdr = n
  inc hdr                    # peek at the target symbol (does not advance n)
  if hdr.kind != Symbol: error("Expected proc symbol or type, got " & $hdr.kind, hdr)
  let name = getSym(hdr)
  let sym = lookupWithAutoImport(ctx, ctx.scope, name, hdr)

  # A prepare block may NEST inside another: arkham emits that for an argument that is
  # itself a call — `f(g(x))`, which hexer leaves unflattened in a global's initializer
  # expression. The inner call is complete before the outer one's following `(arg …)`
  # bindings, so the enclosing context just has to survive it; save it and restore at
  # the end. The one shape that cannot work is an outer call with STACK arguments: both
  # calls write the single outgoing argument area the frame reserves, so the inner one
  # would overwrite what the outer already put there.
  let outerCall = ctx.callContext
  # `> stackArgBase`, not `> 0`: the base is Win64 shadow space, which the CALLEE
  # writes after the call, so two nested calls never contend for it. Genuine stack
  # ARGUMENTS are the conflict — the outer call has already placed some in the one
  # outgoing area the inner call is about to reuse.
  if outerCall.state != CallContextState.Disabled and
     outerCall.stackArgSize > outerCall.stackArgBase:
    error("Nested prepare blocks are not allowed when the outer call passes arguments " &
          "on the stack: both would write the one outgoing argument area", hdr)

  ctx.callContext = CallContext(
    state: CallContextState.NormalCall,
    target: name,
    argsSet: initHashSet[SymId](),
    resultsSet: initHashSet[SymId](),
    callEmitted: false,
    stackArgBase: (if ctx.arch == Arch.WinX64: WinShadowSpace else: 0)
  )

  if sym == nil:
    error("Unknown symbol: " & name, hdr)
  elif sym.kind == skProc:
    # A foreign proc is bundled into this image and called directly (see
    # generateSymbol); only genuine `extproc` externals use the extcall path.
    ctx.callContext.typ = sym.typ
    ctx.callContext.state = CallContextState.NormalCall
  elif sym.kind == skSysProc:
    # A Linux syscall with a full proctype: arg/result checking and register
    # assignment proceed exactly as for a direct call (args land in the syscall
    # ABI registers the proctype names, e.g. arg4 → r10), but the invocation
    # marker is `(syscall)` — `genSyscallMarkerX64` inlines `mov rax,NR; syscall`
    # and applies the proctype's clobbers. No `call`/address is involved.
    ctx.callContext.typ = sym.typ
    ctx.callContext.state = CallContextState.NormalCall
    ctx.callContext.isSyscall = true
    ctx.callContext.syscallNr = sym.offset
  elif sym.kind in {skGvar, skTvar, skVar, skParam} and sym.typ.kind == ProcT:
    # Indirect call through a function-pointer variable: its proctype IS the
    # signature, so arg/result checking and stack layout proceed exactly as for a
    # direct call; only `(call)` differs (it loads the pointer and calls it).
    ctx.callContext.typ = sym.typ
    ctx.callContext.state = CallContextState.NormalCall
    ctx.callContext.indirect = true
  elif sym.kind == skExtProc:
    # A dynamic import: the invocation is an indirect `(extcall)` through the IAT/GOT
    # slot rather than a `call rel32`. If the decl carried a signature (the Windows
    # form — see `parseExtprocSig`) it is checked and laid out exactly like any other
    # call; a bare Darwin extern has no signature to check against, so its call site
    # marshals into raw ABI registers and only the marker is verified below.
    ctx.callContext.state = CallContextState.ExternalCall
    ctx.callContext.typ = sym.typ
    for i, ext in ctx.extProcs:
      if ext.name == name:
        ctx.callContext.extProcIdx = i
        break
  else:
    error("Expected proc symbol, got " & $sym.kind, hdr)

  # Whether the call is checked against a signature — every internal call, plus an
  # extern whose decl declared one.
  let typed = ctx.callContext.typ != nil

  # Compute stack argument size
  if typed:
    ctx.callContext.stackArgSize = ctx.callContext.stackArgBase +
                                   computeStackArgSize(ctx.callContext.typ)
    # Fixed-frame soundness (same as the A64 path): this call's outgoing stack args
    # occupy `[rsp, rsp+stackArgSize)`, the region `scanStackArgArea` reserved at the
    # frame bottom. If the pre-scan missed this target (an indirect call through a
    # not-yet-declared local fn-ptr), the reservation may be too small — fail loudly
    # rather than let the args overwrite a local `(s)` slot.
    if ctx.callContext.stackArgSize > ctx.reservedArgArea:
      error("outgoing stack-argument area (" & $ctx.callContext.stackArgSize &
            " bytes) exceeds the reserved frame area (" & $ctx.reservedArgArea &
            " bytes); call target not visible to the frame pre-scan", hdr)

  # Consume the prepare node: skip the (already-read) target, then generate each
  # instruction. `into` bounds the loop to this node (no ParRi sentinel exists).
  into n:
    skip n                   # the target symbol
    while n.hasMore:
      genInstX64(n, ctx)

  # Verify all bindings are done
  if typed:
    for param in ctx.callContext.typ.params:
      if not param.typ.isOnStack and param.name notin ctx.callContext.argsSet:
        error("Missing argument: " & ctx.nameOf(param.name), hdr)

    for res in ctx.callContext.typ.results:
      if res.name notin ctx.callContext.resultsSet:
        error("Missing result binding: " & ctx.nameOf(res.name), hdr)

  # Verify call was emitted
  if not ctx.callContext.callEmitted:
    if ctx.callContext.state == CallContextState.NormalCall:
      error("Missing (call) or (extcall) in prepare block", hdr)
    else:
      error("Missing (extcall) in prepare block", hdr)
  ctx.callContext = outerCall                  # resume the enclosing call, if any
  if outerCall.state == CallContextState.Disabled:
    ctx.callContext.state = CallContextState.Disabled

proc genCallMarkerX64(n: var Cursor; ctx: var GenContext) =
  ## `(call)` inside a `prepare` block emits the actual call: a direct `call rel32`
  ## to the prepared proc, or — when the prepare target is a function-pointer
  ## variable — an indirect call that loads the pointer and `call`s through it.
  if not ctx.inCall:
    if ctx.lenient:
      # Lenient bare call: `(call P)` with no `(prepare)` ceremony — the
      # ported body has already marshalled its arguments (arkham's ABI is
      # plain SysV, so gcc code's registers line up as-is).
      into n:
        if n.kind != Symbol: error("bare (call P) requires a proc symbol", n)
        let sym = lookupWithAutoImport(ctx, ctx.scope, getSym(n), n)
        if sym == nil:
          error("bare (call P): unknown proc: " & getSym(n), n)
        inc n
        if sym.kind == skProc:
          var labId: LabelId
          if sym.offset == -1:
            labId = ctx.buf.createLabel()
            sym.offset = int(labId)
          else:
            labId = LabelId(sym.offset)
          ctx.buf.emitCall(labId)
        elif sym.kind == skGvar:
          # A GLOBAL holding a function pointer: same lowering as the prepare
          # path — lea the global's address (patched by writeElf), load the
          # pointer, call through RAX (volatile at any call site).
          let pos = x86.emitLeaRipPlaceholder(ctx.buf, x86.RAX)
          ctx.gvarSites.add (pos, sym)
          x86.emitMov(ctx.buf.data, x86.RAX,
                      x86.MemoryOperand(base: x86.RAX))
          x86.emitCallReg(ctx.buf.data, x86.RAX)
        else:
          error("bare (call P): not a proc or fn-pointer global: " & $sym.kind, n)
      return
    error("(call) can only be used inside a prepare block", n)

  if ctx.callContext.callEmitted:
    error("Multiple (call) instructions in prepare block", n)
  if ctx.callContext.state == CallContextState.ExternalCall:
    error("Use (extcall) for external procs, not (call)", n)

  let sym = lookupWithAutoImport(ctx, ctx.scope, ctx.callContext.target, n)

  # Clobber registers
  ctx.clobbered.incl(ctx.callContext.typ.clobbers)

  if ctx.callContext.indirect:
    if sym.kind in {skVar, skParam} and sym.reg != InvalidTagId:
      # A function pointer held directly in a REGISTER (e.g. arkham's vtable-method load,
      # or a reg-resident `var f: proc`): the register holds the code address itself, so
      # `call reg` — no load. (The register is caller-saved/non-arg per the proctype's
      # clobber, so the prepared args in rdi…r9 are untouched.)
      x86.emitCallReg(ctx.buf.data, tagToRegister(sym.reg, n))
    else:
      # A function pointer stored in a GLOBAL: form its RIP-relative address (recorded as
      # a site, patched by writeElf like a `(lea reg gvar)`), load the pointer, call it.
      let pos = x86.emitLeaRipPlaceholder(ctx.buf, x86.RAX)               # lea rax, [rip+fnptr]
      ctx.gvarSites.add (pos, sym)
      x86.emitMov(ctx.buf.data, x86.RAX, x86.MemoryOperand(base: x86.RAX)) # mov rax, [rax]
      x86.emitCallReg(ctx.buf.data, x86.RAX)                              # call rax
  else:
    var labId: LabelId
    if sym.offset == -1:
      labId = ctx.buf.createLabel()
      sym.offset = int(labId)
    else:
      labId = LabelId(sym.offset)
    ctx.buf.emitCall(labId)
  ctx.callContext.callEmitted = true
  inc n                   # past the `(call` head

proc genSyscallMarkerX64(n: var Cursor; ctx: var GenContext) =
  ## `(syscall)` inside a `(prepare <syproc> …)` block: the syscall counterpart of
  ## `(call)`. The args are already in the syscall ABI registers (the syproc's
  ## params), so this just loads the number into rax and traps into the kernel,
  ## then marks rcx/r11 clobbered (the registers the `syscall` instruction
  ## destroys, declared as the syproc's `(clobber …)`). The result is in rax.
  if ctx.callContext.callEmitted:
    error("Multiple call/syscall instructions in prepare block", n)
  x86.emitMovImmToReg(ctx.buf.data, x86.RAX, int64(ctx.callContext.syscallNr))
  x86.emitSyscall(ctx.buf.data)
  ctx.clobbered.incl(ctx.callContext.typ.clobbers)
  ctx.callContext.callEmitted = true
  inc n                   # past the `(syscall)` head

proc genExtcallX64(n: var Cursor; ctx: var GenContext) =
  ## Handle (extcall) marker inside a prepare block - emits external call via IAT
  if not ctx.inCall:
    error("(extcall) can only be used inside a prepare block", n)

  if ctx.callContext.callEmitted:
    error("Multiple call instructions in prepare block", n)
  if ctx.callContext.state == CallContextState.NormalCall:
    error("Use (call) for internal procs, not (extcall)", n)

  # The registers the callee destroys — declared by a signature-carrying extern, so a
  # value the caller left bound in one is reported rather than silently read back after
  # the call. (A bare extern declares none; its call site marshals raw and binds nothing.)
  if ctx.callContext.typ != nil:
    ctx.clobbered.incl(ctx.callContext.typ.clobbers)

  # Record call site and emit IAT call
  let callPos = ctx.buf.data.len
  ctx.extProcs[ctx.callContext.extProcIdx].callSites.add callPos
  ctx.buf.emitIatCall(ctx.extProcs[ctx.callContext.extProcIdx].gotSlot)

  ctx.callContext.callEmitted = true

  inc n

  #for (res, dest) in boundResults:
  #  let resReg = tagToRegister(res.reg)
  #  if dest.reg != resReg:
  #    x86.emitMov(ctx.buf.data, dest.reg, resReg)

proc genIatX64(n: var Cursor; ctx: var GenContext) =
  # (iat symbol) - Indirect call through IAT for external procs
  inc n
  if n.kind != Symbol: error("Expected proc symbol for iat", n)
  let name = getSym(n)
  let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
  if sym == nil or sym.kind != skExtProc: error("iat requires external proc, got: " & name, n)
  inc n
  # Find the extproc to get its IAT slot
  var iatSlot = -1
  for i in 0..<ctx.extProcs.len:
    if ctx.extProcs[i].name == name:
      iatSlot = ctx.extProcs[i].gotSlot
      break
  if iatSlot == -1:
    error("External proc not found: " & name, n)
  # Emit indirect call through IAT using relocation system
  ctx.buf.emitIatCall(iatSlot)

proc genMovX64(n: var Cursor; ctx: var GenContext) =
  let start = n
  inc n
  let dest = parseDest(n, ctx)
  let op = parseOperand(n, ctx)

  # Type checking against THE shared rule (`movTypeOk`), the same one the a64 `mov`
  # applies — see it for what each admitted pairing rests on.
  if not movTypeOk(dest.kind, dest.typ, op.kind, op.typ):
    typeError(dest.typ, op.typ, start)
  checkPtrStore(dest.typ, op.kind, op.typ, start)

  if dest.kind == okMem:
    if op.kind == okImm:
      # `mov r/m, imm32` (C7 /0), sign-extended into a 64-bit destination and
      # SIZED like every other store here so a narrow field's neighbours survive.
      if op.immVal >= low(int32) and op.immVal <= high(int32):
        x86.emitMovImmToMem(ctx.buf.data, dest.mem, int32(op.immVal),
                            intMemAccess(dest.typ).bits)
      else:
        error("Immediate too large for memory move (must fit in 32 bits)", n)
    elif op.kind == okSsize:
      # Similar issue, ssize is immediate 0 (patched).
      error("Moving ssize to memory not supported", n)
    elif op.kind == okMem:
      error("Cannot move memory to memory", n)
    else:
      let (bits, _) = intMemAccess(dest.typ)     # sized store: don't clobber neighbors
      x86.emitMovToMemSized(ctx.buf.data, dest.mem, op.reg, bits)
  else:
    # dest is reg
    if op.kind == okSsize:
      x86.emitMovImmToReg32(ctx.buf.data, dest.reg, 0)
      ctx.ssizePatches.add((ctx.buf.data.len - 4, int(op.immVal)))
    elif op.kind == okCsize:
      # csize is a known value - the stack argument size for the current call
      x86.emitMovImmToReg32(ctx.buf.data, dest.reg, int32(op.immVal))
    elif op.kind == okImm:
      if op.immVal >= low(int32) and op.immVal <= high(int32):
        x86.emitMovImmToReg32(ctx.buf.data, dest.reg, int32(op.immVal))
      else:
        x86.emitMovImmToReg(ctx.buf.data, dest.reg, op.immVal)
    elif op.kind == okMem:
      let (bits, signed) = intMemAccess(op.typ)  # sized load: sign-/zero-extend sub-word
      x86.emitLoadExt(ctx.buf.data, dest.reg, op.mem, bits, signed)
    elif dest.reg != op.reg:
      x86.emitMov(ctx.buf.data, dest.reg, op.reg)
    # else: a redundant same-register move — elide it. The declarative-call
    # `(arg …)`/`(res …)` markers resolve to a fixed ABI register, so a value
    # already in that register marshals to `(mov (arg pN) (rN))` == `mov rN,rN`.
    # arkham's own `movReg` elides d==s; this mirrors it for the marshalling path.

    # A register destination now holds a freshly-written value, so an earlier call's
    # clobber no longer applies — mirror LeaX64 (5211) and the a64 mov (1877). This is
    # what lets a caller-save reload `(mov x.0 <slot>)` (x.0 bound to a call-clobbered
    # volatile) pass the clobber verifier: the reload re-defines the register. Sound —
    # `parseOperand` still rejects reading a clobbered SOURCE; a mov defines its dest.
    ctx.clobbered.excl(dest.reg)

proc genIteX64(n: var Cursor; ctx: var GenContext) =
  inc n

  # Check if condition is a cfvar (symbol) or a hardware flag (parens)
  let lElse = ctx.buf.createLabel()
  let lEnd = ctx.buf.createLabel()

  # Save clobbered state
  let oldClobbered = ctx.clobbered

  if n.kind == Symbol:
    # Control flow variable: (ite cfvar ...)
    let name = getSym(n)
    let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
    if sym == nil or sym.kind != skCfvar: error("Expected cfvar in ite condition: " & name, n)

    # Check if this cfvar has already been used
    if sym.used:
      error("Control flow variable '" & name & "' used more than once", n)
    sym.used = true

    inc n

    # When using a cfvar in ite, we don't emit any jump here.
    # The cfvar's label should be defined at the start of the "then" branch.
    # If jtrue was called, it jumped directly to the "then" branch.
    # If jtrue was NOT called, execution falls through to the "else" branch.

    # We need to emit an unconditional jump to else before the then branch
    ctx.buf.emitJmp(lElse)

    # Define the cfvar's label here (start of then branch)
    ctx.buf.defineLabel(LabelId(sym.offset))

  elif n.kind == TagLit:
    # Hardware flag: (ite (flag) ...)
    let flagTag = tagToX64Flag(n.tag)
    inc n
    inc n

    case flagTag
    of OfO: ctx.buf.emitJno(lElse)
    of NoO: ctx.buf.emitJo(lElse)
    of ZfO: ctx.buf.emitJne(lElse)
    of NzO: ctx.buf.emitJe(lElse)
    of SfO: ctx.buf.emitJns(lElse)
    of NsO: ctx.buf.emitJs(lElse)
    of CfO: ctx.buf.emitJae(lElse)
    of NcO: ctx.buf.emitJb(lElse)
    of PfO: ctx.buf.emitJnp(lElse)
    of NpO: ctx.buf.emitJp(lElse)
    else: error("Unsupported condition: " & $flagTag, n)
  else:
    error("Expected cfvar or flag condition in ite", n)

  genStmt(n, ctx) # Then block
  # Clobbered state propagates?
  # Control flow merge: union of clobbered sets?
  # If a register is clobbered in THEN but not ELSE, it is clobbered after? Yes.
  let thenClobbered = ctx.clobbered

  ctx.buf.emitJmp(lEnd)

  ctx.clobbered = oldClobbered # Reset for Else
  ctx.buf.defineLabel(lElse)
  genStmt(n, ctx) # Else block
  let elseClobbered = ctx.clobbered

  ctx.buf.defineLabel(lEnd)

  # Merge clobbered
  ctx.clobbered = thenClobbered + elseClobbered


proc genLoopX64(n: var Cursor; ctx: var GenContext) =
  inc n

  # Bare infinite-loop form `(loop (stmts …))` — the body is a single statement block. The
  # back-edge is emitted INTERNALLY here, so no token-level backward `jmp` reaches the input:
  # the body carries a FORWARD `jmp` to a break/exit label defined AFTER the loop. This is
  # the form arkham emits for every loop; it keeps "every `jmp` is forward, back-edges are
  # `loop`" true. (The legacy `(loop <pre> <condflag> <body>)` cfvar form below is unused.)
  if atTag(n, StmtsTagId):
    let lStart = ctx.buf.createLabel()
    ctx.buf.defineLabel(lStart)
    genStmt(n, ctx)                 # the body (contains the forward break/exit jmp)
    ctx.buf.emitJmp(lStart)         # the loop back-edge — emitted by nifasm, not the input
    return

  # Pre-loop
  genStmt(n, ctx)
  let lStart = ctx.buf.createLabel()
  let lEnd = ctx.buf.createLabel()

  ctx.buf.defineLabel(lStart)

  if n.kind != TagLit: error("Expected condition", n)
  let condTag = n.tag
  inc n

  let loopFlagTag = tagToX64Flag(condTag)
  case loopFlagTag
  of ZfO: ctx.buf.emitJne(lEnd)
  of NzO: ctx.buf.emitJe(lEnd)
  else: error("Unsupported loop condition: " & $loopFlagTag, n)

  # Body
  genStmt(n, ctx)
  ctx.buf.emitJmp(lStart)
  ctx.buf.defineLabel(lEnd)

  # Loop body clobbers propagate
  # But we might execute loop 0 times?
  # If it's a while loop check at start (which this seems to be? No, structure is (loop pre cond post)?)
  # "As in NJVL... (loop (stmts) (cond) (stmts))"
  # It's a do-while or mid-test loop.
  # If we execute the body, clobbers happen.
  # If we skip, they don't?
  # "All control flow variables are always virtual... The first implementations... do not check if these jumps would skip useful instructions"
  # For clobber tracking, we should assume body MIGHT run.
  # So union with pre-loop state?
  # But `ctx.clobbered` accumulates.
  # So whatever happened in body is added.

proc genJtrueX64(n: var Cursor; ctx: var GenContext) =
  # (jtrue cfvar1.0 cfvar2.0 ...)
  # Set control flow variable(s) to true by emitting an unconditional jump
  # The jump targets are stored in the cfvar symbols
  let start = n
  inc n
  var jumpTarget: LabelId
  var firstCfvar = true

  while n.kind == Symbol:
    let name = getSym(n)
    let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
    if sym == nil: error("Unknown cfvar: " & name, n)
    if sym.kind != skCfvar: error("Symbol is not a cfvar: " & name, n)

    if firstCfvar:
      jumpTarget = LabelId(sym.offset)
      firstCfvar = false
    # For multiple cfvars, they all jump to the same place (first one's target)
    # This matches the semantics where all are set to true together
    inc n

  if firstCfvar: error("jtrue requires at least one cfvar", start)

  # Emit unconditional jump to the cfvar's target label
  ctx.buf.emitJmp(jumpTarget)


proc genKillX64(n: var Cursor; ctx: var GenContext) =
  inc n
  if n.kind != Symbol: error("Expected symbol to kill", n)
  let name = getSym(n)
  let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
  if sym == nil: error("Unknown variable to kill: " & name, n)

  if sym.typ.isOnStack:
    ctx.slots.killSlot(sym.offset, sym.typ)
  elif sym.reg != InvalidTagId:
    # Remove register binding when variable is killed
    if isXmmTagEnum(sym.reg):
      ctx.xmmBindings.del(tagToXmm(sym.reg))
    else:
      ctx.regBindings.del(tagToRegister(sym.reg, n))

  # Remove from scope to ensure it's not used again
  ctx.scope.undefine(sym.name)

  inc n

proc checkFixedRegFree(ctx: GenContext; reg: x86.Register; insn: string; n: Cursor) =
  if ctx.lenient: return
  ## A fixed-register instruction (`idiv`/`div` write RDX:RAX) is about to clobber
  ## `reg`. If a live variable is still bound to it, that is a code-generator bug —
  ## the clobber would silently destroy the value. Reject it: the value must be moved
  ## (or the binding `kill`ed / `rebind`ed) first. Without this the raw `(rdx)`/`(rax)`
  ## operands bypass `parseOperand`'s binding check, which is how a live parameter
  ## sitting in RDX/RCX used to be miscompiled in silence.
  if reg in ctx.regBindings:
    error(insn & " clobbers " & $reg & ", still bound to variable '" &
          ctx.regBindings[reg] & "' — move/kill it first", n)

proc bindRegX64(ctx: var GenContext; name: string; typ: Type; regTag: TagEnum;
                reg: x86.Register) =
  ## Bind physical register `reg` to the typed name `name`, *killing its prior
  ## tenant first*: the previous binding's name is undefined, so a later use of a
  ## value wrongly left in that register becomes an "Unknown variable" error rather
  ## than a silent clobber. This is the "(re)bind implies a kill (of the prior
  ## tenant)" rule shared by `rebind` and `withreg`.
  if reg in ctx.regBindings:
    ctx.scope.undefine(ctx.symIdOf(ctx.regBindings[reg]))
    ctx.regBindings.del(reg)
  # Establishing a fresh binding abandons whatever a prior call left in `reg`: arkham
  # only rebinds-at-borrow right before writing the scratch, so the register's stale
  # clobbered status no longer applies (it would otherwise reject a scratch temp that
  # happens to reuse a caller-saved register clobbered by an earlier call).
  ctx.clobbered.excl(reg)
  let sym = Symbol(name: ctx.symIdOf(name), kind: skVar, typ: typ)
  sym.reg = regTag
  ctx.regBindings[reg] = name
  ctx.scope.define(sym)

proc bindXmmX64(ctx: var GenContext; name: string; typ: Type; xmmTag: TagEnum;
                xmm: x86.XmmRegister) =
  ## The SIMD twin of `bindRegX64`: bind xmm register `xmm` to the typed float name
  ## `name`, killing its prior tenant first. Used for float register locals and
  ## float scratch temps.
  if xmm in ctx.xmmBindings:
    ctx.scope.undefine(ctx.symIdOf(ctx.xmmBindings[xmm]))
    ctx.xmmBindings.del(xmm)
  let sym = Symbol(name: ctx.symIdOf(name), kind: skVar, typ: typ)
  sym.reg = xmmTag
  ctx.xmmBindings[xmm] = name
  ctx.scope.define(sym)

proc parseRebindHeader(n: var Cursor; ctx: var GenContext):
                       tuple[name: string; typ: Type; isXmm: bool;
                             regTag: TagEnum; reg: x86.Register; xmm: x86.XmmRegister] =
  ## Parse `:name TYPE (reg)` (the cursor is past the rebind/withreg tag, inside the
  ## node) and establish the binding. Shared by `rebind` and `withreg`. The register
  ## may be a GPR (`(rN)`) or — for a float binding — an xmm register (`(xmmN)`).
  if n.kind != SymbolDef: error("Expected name for rebind/withreg", n)
  result.name = symName(n); inc n
  result.typ = parseType(n, ctx.scope, ctx)
  if isXmmTag(n):
    result.isXmm = true
    result.regTag = n.tag
    result.xmm = tagToXmm(result.regTag)
    inc n
    bindXmmX64(ctx, result.name, result.typ, result.regTag, result.xmm)
  elif n.kind == TagLit and rawTagIsX64Reg(n.tag):
    result.regTag = n.tag
    result.reg = tagToRegister(result.regTag, n)
    inc n
    bindRegX64(ctx, result.name, result.typ, result.regTag, result.reg)
  else:
    error("Expected a register for rebind/withreg", n)

proc genRebindX64(n: var Cursor; ctx: var GenContext) =
  ## `(rebind :name TYPE (reg))` — bind `reg` to `name`, killing its prior tenant.
  ## The binding lives until an explicit `kill`, the next `rebind` of `reg`, or the
  ## end of the proc (`regBindings` is reset per proc — the auto-kill backstop).
  into n:
    discard parseRebindHeader(n, ctx)

proc genWithregX64(n: var Cursor; ctx: var GenContext) =
  ## `(withreg :name TYPE (reg) body…)` — a block-scoped `rebind`: the binding is
  ## auto-killed at the end of the body (its own implied kill), in addition to
  ## killing `reg`'s prior tenant on entry.
  into n:
    let h = parseRebindHeader(n, ctx)
    while n.hasMore: genInstX64(n, ctx)
    if h.isXmm:
      if ctx.xmmBindings.getOrDefault(h.xmm, "") == h.name:
        ctx.xmmBindings.del(h.xmm)
    elif ctx.regBindings.getOrDefault(h.reg, "") == h.name:
      ctx.regBindings.del(h.reg)
    ctx.scope.undefine(ctx.symIdOf(h.name))

proc leaRegBase(n: var Cursor; ctx: var GenContext; baseReg: var x86.Register): bool =
  ## Detect and consume a `lea` base register: a raw `(reg)` tag, or a
  ## register-bound local name (a `rebind`'d scratch temp now reaches `lea` by name,
  ## not as a raw reg). Leaves `n` untouched and returns false for any other operand
  ## (label / gvar / mem / dot / at — handled by `parseOperand` instead).
  if n.kind == TagLit and rawTagIsX64Reg(n.tag):
    baseReg = parseRegister(n); return true
  if n.kind == Symbol:
    let s = lookupWithAutoImport(ctx, ctx.scope, getSym(n), n)
    if s != nil and (s.kind == skVar or s.kind == skParam) and
       not s.typ.isOnStack and s.reg != InvalidTagId:
      baseReg = tagToRegister(s.reg, n); inc n; return true
  return false

proc checkDistinctAluRegs(dest, op: Operand; mnemonic: string; n: Cursor) =
  if gLenient: return
  ## A register `and`/`or`/`sub` whose two operands are the SAME register is never
  ## intentional in arkham's codegen: `x and x == x`, `x or x == x`, `x - x == 0`,
  ## so the real source operand has been dropped — the signature of a staging /
  ## scratch register colliding with the destination (e.g. the set-membership
  ## `setbyte and mask` degrading to `setbyte and setbyte`). nifasm is the strict
  ## checker that must catch such a value-dropping miscompile at assemble time
  ## instead of leaving it to surface at runtime. (`xor`/`test`/`cmp` with equal
  ## registers ARE idioms — zero a register / test for zero — so they are excluded.)
  if dest.kind == okReg and op.kind == okReg and dest.reg == op.reg:
    error("`" & mnemonic & "` with identical register operands (" & $dest.reg &
          ") — dropped source operand (staging/scratch register collided with the " &
          "destination); the value-carrying register must be a distinct typed binding", n)

proc shiftCodePositions(ctx: var GenContext; at, by: int) =
  ## Rebase every recorded byte position `>= at` by `by` freshly inserted bytes
  ## (the `casejmp` NOP padding). A label/reloc exactly AT the insert point
  ## belongs to the code AFTER the padding (the next slot), so `>=` is right —
  ## which is also why a casejmp branch body must not define a label at its very
  ## end (see doc/instructions.md).
  for k in 0 ..< ctx.buf.relocs.len:
    if ctx.buf.relocs[k].position >= at: ctx.buf.relocs[k].position += by
  for k in 0 ..< ctx.buf.labels.len:
    if ctx.buf.labels[k].position >= at: ctx.buf.labels[k].position += by
  for k in 0 ..< ctx.buf.fixedRanges.len:      # a NESTED casejmp region inside a slot
    let (s, e) = ctx.buf.fixedRanges[k]
    ctx.buf.fixedRanges[k] = ((if s >= at: s + by else: s), (if e >= at: e + by else: e))
  for k in 0 ..< ctx.gvarSites.len:
    if ctx.gvarSites[k][0] >= at: ctx.gvarSites[k] = (ctx.gvarSites[k][0] + by, ctx.gvarSites[k][1])
  for k in 0 ..< ctx.ssizePatches.len:
    if ctx.ssizePatches[k].pos >= at: ctx.ssizePatches[k].pos += by
  for k in 0 ..< ctx.csizePatches.len:
    if ctx.csizePatches[k][0] >= at: ctx.csizePatches[k] = (ctx.csizePatches[k][0] + by, ctx.csizePatches[k][1])
  for k in 0 ..< ctx.tlvSites.len:
    if ctx.tlvSites[k][0] >= at: ctx.tlvSites[k] = (ctx.tlvSites[k][0] + by, ctx.tlvSites[k][1])
  # An EXTERNAL call's `bl` is not a reloc — its position is recorded per extproc and
  # patched at image layout — so it needs rebasing here too. Missing it left the `bl`
  # unpatched (a branch to itself) and wrote the IAT displacement over whatever had
  # moved into the stale slot, which for a pruned frame `add` was the epilogue's
  # `add sp, sp, #frame`.
  for e in 0 ..< ctx.extProcs.len:
    for k in 0 ..< ctx.extProcs[e].callSites.len:
      if ctx.extProcs[e].callSites[k] >= at: ctx.extProcs[e].callSites[k] += by
  for k in 0 ..< ctx.listRows.len:      # `--listing` byte ranges
    if ctx.listRows[k].start >= at: ctx.listRows[k].start += by
    if ctx.listRows[k].stop >= at: ctx.listRows[k].stop += by
  for k in 0 ..< ctx.unwind.len:        # `.symtab` / `.eh_frame` proc + CFI positions
    if ctx.unwind[k].start >= at: ctx.unwind[k].start += by
    if ctx.unwind[k].stop >= at: ctx.unwind[k].stop += by
    for s in 0 ..< ctx.unwind[k].steps.len:
      if ctx.unwind[k].steps[s].at >= at: ctx.unwind[k].steps[s].at += by

proc genCasejmpX64(n: var Cursor; ctx: var GenContext) =
  ## `(casejmp S T (stmts …)+)` — computed-goto case dispatch (issue #32). The
  ## k-th `(stmts …)` child is slot k's branch body. Bodies are emitted
  ## back-to-back and NOP-padded to the measured uniform slot size N, so the
  ## dispatch is pure arithmetic — no lookup table, no memory load:
  ##     imul S, S, N          ; slot index → byte offset (N patched below)
  ##     lea  T, [rip+slots]   ; T ← &slot0
  ##     add  T, S
  ##     jmp  T                ; the pad NOPs are never executed
  ## Every body must end in a terminating jump/exit (arkham emits `jmp lEnd`),
  ## so falling into the padding is impossible. The [slots, end) region is
  ## registered as a layout-frozen `fixedRange`: the jump optimizers must not
  ## delete/invert/shrink instructions inside, or `T + S*N` lands mid-instruction.
  let start = n
  intoOperands n:                # `casejmp` is an x86-64-only mnemonic, so its
                                 # id may not fit a tag — see tagpool.nim
    # S: the slot-index register (read, then destroyed by the imul). A raw `(reg)`
    # or a register-bound local name; parseOperand also runs the clobber check.
    let selOp = parseOperand(n, ctx)
    if selOp.kind != okReg:
      error("casejmp selector must be a register or register-bound local", start)
    # T: the base scratch — write-only, so parse it like a `lea` destination.
    var baseReg: x86.Register
    if not leaRegBase(n, ctx, baseReg):
      error("casejmp scratch must be a register or register-bound local", start)
    if baseReg == selOp.reg:
      error("casejmp scratch and selector occupy the same register (" & $baseReg & ")", start)
    # ── dispatch preamble: fixed byte size, independent of the patched N ──
    x86.emitImulImm(ctx.buf.data, selOp.reg, 0)      # S *= N (imm32 patched below)
    let immPos = ctx.buf.data.len - 4
    let slotsLab = ctx.buf.createLabel()
    x86.emitLea(ctx.buf, baseReg, slotsLab)          # T ← &slot0 (rkLea, always 7 bytes)
    x86.emitAdd(ctx.buf.data, baseReg, selOp.reg)
    x86.emitJmpReg(ctx.buf.data, baseReg)
    ctx.clobbered.excl(selOp.reg)                    # both are freshly written here
    ctx.clobbered.excl(baseReg)
    # ── slot bodies, back-to-back; measure each. Slots execute EXCLUSIVELY
    # (exactly one runs per dispatch), so clobber state forks per slot and
    # merges as the union — same rule as `ite`'s branches. ──
    ctx.buf.defineLabel(slotsLab)
    let slotsStart = ctx.buf.data.len
    let clobBefore = ctx.clobbered
    var clobUnion = ctx.clobbered
    var bounds: seq[(int, int)] = @[]
    while n.hasMore:
      if not (n.kind == TagLit and n.tag == StmtsTagId):
        error("casejmp children must be (stmts …) branch bodies", n)
      let s = ctx.buf.data.len
      ctx.clobbered = clobBefore
      genInstX64(n, ctx)                             # the StmtsX64 arm drains the body
      clobUnion = clobUnion + ctx.clobbered
      bounds.add (s, ctx.buf.data.len)
    ctx.clobbered = clobUnion
    if bounds.len == 0:
      error("casejmp requires at least one (stmts …) branch body", start)
    var slotSize = 0
    for (s, e) in bounds: slotSize = max(slotSize, e - s)
    # ── NOP-pad every slot to the uniform size, last-to-first so earlier insert
    # points stay valid; every recorded position past an insert is rebased ──
    for i in countdown(bounds.len - 1, 0):
      let (s, e) = bounds[i]
      let pad = slotSize - (e - s)
      if pad > 0:
        insertRepeated(ctx.buf.data, e, 0x90'u8, pad)
        shiftCodePositions(ctx, e, pad)
    # patch the measured slot size into the imul (immPos precedes the region: stable)
    let nv = uint32(slotSize)
    ctx.buf.data[immPos]     = byte(nv and 0xFF)
    ctx.buf.data[immPos + 1] = byte((nv shr 8) and 0xFF)
    ctx.buf.data[immPos + 2] = byte((nv shr 16) and 0xFF)
    ctx.buf.data[immPos + 3] = byte((nv shr 24) and 0xFF)
    ctx.buf.fixedRanges.add (slotsStart, slotsStart + bounds.len * slotSize)

type
  SizedAluKind = enum
    saAdd, saSub, saAnd, saOr, saXor, saCmp, saTest

const
  # MR-form opcode pairs (8-bit / 16-32-bit) and the /digit of the imm form,
  # indexed by SizedAluKind. TEST's imm form is special-cased (0xF6/0xF7 /0).
  sizedAluOpcMR8: array[SizedAluKind, byte] = [0x00'u8, 0x28, 0x20, 0x08, 0x30, 0x38, 0x84]
  sizedAluOpcMR:  array[SizedAluKind, byte] = [0x01'u8, 0x29, 0x21, 0x09, 0x31, 0x39, 0x85]
  sizedAluOpcRM8: array[SizedAluKind, byte] = [0x02'u8, 0x2A, 0x22, 0x0A, 0x32, 0x3A, 0x84]
  sizedAluOpcRM:  array[SizedAluKind, byte] = [0x03'u8, 0x2B, 0x23, 0x0B, 0x33, 0x3B, 0x85]
  sizedAluDigit:  array[SizedAluKind, int]  = [0, 5, 4, 1, 6, 7, 0]

proc checkSubWidthImm(imm: int64; bits: int; n: Cursor) =
  ## The immediate must fit the operation width under EITHER signedness —
  ## only its low `bits` reach the hardware, so `(cmp (cast (u 8) r) 255)`
  ## and `(cmp (cast (i 8) r) -1)` are both meaningful (and identical).
  let lo = -(1'i64 shl (bits - 1))
  let hi = (1'i64 shl bits) - 1
  if imm < lo or imm > hi:
    error("immediate " & $imm & " does not fit a " & $bits &
          "-bit sub-width operation", n)

proc genAluSubWidth(ctx: var GenContext; dest, op: Operand; kind: SizedAluKind;
                    n: Cursor) =
  ## Two-operand ALU whose destination is an explicitly width-cast register:
  ## the operation runs at `dest.castBits` (8/16/32). A 32-bit op zero-extends
  ## the destination, 8/16-bit ops preserve its upper bits, flags are set at
  ## the operation width — the hardware's own sub-width semantics. The source
  ## may be an immediate or a register; a cast on the source register must
  ## agree (an uncast one contributes its low bits, which is what the
  ## instruction reads anyway).
  let bits = dest.castBits
  case op.kind
  of okImm:
    checkSubWidthImm(op.immVal, bits, n)
    let imm = cast[int32](uint32(op.immVal and 0xFFFFFFFF'i64))
    if kind == saTest:
      x86.emitTestImmSizedR(ctx.buf.data, dest.reg, imm, bits)
    else:
      x86.emitAluImmSizedR(ctx.buf.data, dest.reg, imm, sizedAluDigit[kind], bits)
  of okReg:
    if op.castBits != 0 and op.castBits != bits:
      error("sub-width operand widths disagree: " & $bits & " vs " &
            $op.castBits, n)
    if kind == saTest:
      x86.emitTestSizedRR(ctx.buf.data, dest.reg, op.reg, bits)
    else:
      x86.emitAluSizedRR(ctx.buf.data, dest.reg, op.reg,
                         sizedAluOpcMR8[kind], sizedAluOpcMR[kind], bits)
  of okMem:
    # reg(cast) OP mem — the memory side is read at the same width.
    if kind == saTest:
      error("TEST with memory operand not supported yet", n)
    x86.emitAluSizedRM(ctx.buf.data, dest.reg, op.mem,
                       sizedAluOpcRM8[kind], sizedAluOpcRM[kind], bits)
  else:
    error("sub-width ALU source must be a register or immediate", n)

proc genInstX64(n: var Cursor; ctx: var GenContext) =
  if n.kind != TagLit: error("Expected instruction", n)
  let instTag = tagToX64Inst(n.tag)
  let start = n

  let declTag = tagToNifasmDecl(n.tag)
  case declTag
  of CfvarD:
    # (cfvar :name.0)
    inc n
    if n.kind != SymbolDef: error("Expected cfvar name", n)
    let name = symName(n)
    inc n

    # Control flow variables are always virtual (bool type, never materialized)
    # We create a label for when this cfvar becomes "true"
    let cfvarLabel = ctx.buf.createLabel()
    let sym = Symbol(name: ctx.symIdOf(name), kind: skCfvar, typ: Type(kind: BoolT), offset: int(cfvarLabel), used: false)
    ctx.scope.define(sym)

    return

  of VarD:
    inc n
    if n.kind != SymbolDef: error("Expected var name", n)
    let name = symName(n)
    inc n
    var reg = InvalidTagId
    var onStack = false
    var slotAlign = asmWordSize()
    if n.kind == TagLit:
      let locTag = n.tag
      if rawTagIsX64Reg(locTag):
        reg = locTag
        inc n
      elif locTag == STagId:
        onStack = true
        slotAlign = parseSlotAlign(n)         # reads (s (align N)); advances past (s …)
      else:
        error("Expected location", n)
    else:
      error("Expected location", n)
    let baseTyp = parseType(n, ctx.scope, ctx)

    let sym = Symbol(name: ctx.symIdOf(name), kind: skVar)
    if onStack:
      sym.typ = Type(kind: StackOffT, offType: baseTyp)
      # Positive, base-relative offsets (like AArch64): the code generator lowers
      # rsp by a 16-aligned `sub rsp, (ssize)` so the slots sit ABOVE rsp, where a
      # `call`'s pushed return address (and any callee pushes) can't reach them. A
      # red-zone (negative-offset) slot whose address escapes into a call would be
      # clobbered by that call. No frame pointer is needed.
      sym.offset = ctx.slots.allocSlotUp(baseTyp, slotAlign)
    else:
      sym.typ = baseTyp
      sym.reg = reg
      # Check if register is already bound to another variable
      let targetReg = tagToRegister(reg, n)
      if targetReg in ctx.regBindings:
        error("Register " & $targetReg & " is already bound to variable '" &
              ctx.regBindings[targetReg] & "', kill it first before reusing", n)
      # Track the register binding
      ctx.regBindings[targetReg] = name

    ctx.scope.define(sym)

    return
  of NoDecl:
    discard "continue with case instTag"
  of TypeD, ProcD, ParamsD, ParamD, ResultD, ClobberD, LenientD, ArchD, RodataD, GvarD, TvarD, ImpD, ExtprocD, SyprocD, RegsD:
    error("Unexpected declaration: " & $declTag, n)

  # A mnemonic whose id overflowed the 9-bit tag field carries that id in a
  # leading child (see tagpool.nim), so step over it HERE, once, rather than in
  # each of the ~90 arms below: nifcore has no closing token, so a node is
  # consumed by walking its children, and every arm's own `inc n` then lands on
  # the first operand either way. Only the tags numbered up front reach an arm
  # that treats `n` as a whole node again (`(stmts …)`, `(scope …)`, `(ite …)`),
  # and those can never overflow — `gen_instructions` numbers them first.
  if isEscapedTag(n): inc n

  case instTag
  of NoX64Inst:
    error("No x86 instruction", start)
  of StmtsX64:
    loopInto n:
      genInstX64(n, ctx)
  of ScopeX64:
    # A `(scope …)` is a `(stmts …)` with a reclaimable stack-slot arena: `(s)`
    # locals declared inside are freed when the scope closes, so sibling scopes
    # (e.g. the caller-save spill slots of consecutive calls) reuse the same
    # frame bytes. Sound because a call is straight-line control flow — the saved
    # values are restored before the scope ends, so nothing outside the scope
    # observes those slots. The prologue still reserves the peak via `maxStackSize`.
    let savedStackSize = ctx.slots.stackSize
    loopInto n:
      genInstX64(n, ctx)
    ctx.slots.maxStackSize = max(ctx.slots.maxStackSize, ctx.slots.stackSize)
    ctx.slots.stackSize = savedStackSize
  of PrepareX64:
    genPrepareX64(n, ctx)
  of CallX64:
    genCallMarkerX64(n, ctx)
  of ExtcallX64:
    genExtcallX64(n, ctx)
  of IatX64:
    genIatX64(n, ctx)

  of MovX64:
    genMovX64(n, ctx)
  of IteX64:
    genIteX64(n, ctx)
  of LoopX64:
    genLoopX64(n, ctx)
  of JtrueX64:
    genJtrueX64(n, ctx)
  of KillX64:
    genKillX64(n, ctx)
  of RebindX64:
    genRebindX64(n, ctx)
  of WithregX64:
    genWithregX64(n, ctx)
  of AddX64:
    inc n
    let dest = parseDest(n, ctx, allowWidthCast = true)
    let op = parseOperand(n, ctx)

    # Type check: add works on integers and pointers
    checkIntegerArithmetic(dest.typ, "add", start)
    checkIntegerArithmetic(op.typ, "add", start)
    checkArithCompatible(dest.typ, op.typ, "add", start)  # sized ints of any width (64-bit reg)

    if dest.kind == okReg and dest.castBits != 0:
      genAluSubWidth(ctx, dest, op, saAdd, start)
    elif dest.kind == okMem:
      if op.kind == okImm or op.kind == okCsize:
        x86.emitAddImm(ctx.buf.data, dest.mem, int32(op.immVal), intMemAccess(dest.typ).bits)  # ADD m, imm (sized)
      elif op.kind == okSsize:
        error("Adding ssize to memory not supported", n)
      elif op.kind == okMem:
        error("Cannot add memory to memory", n)
      else:
        x86.emitAluSizedMR(ctx.buf.data, dest.mem, op.reg, 0x00, 0x01, intMemAccess(dest.typ).bits)
    else:
      if op.kind == okSsize:
        x86.emitAddImm32(ctx.buf.data, dest.reg, 0)   # forced imm32: back-patched
        ctx.ssizePatches.add((ctx.buf.data.len - 4, int(op.immVal)))
      elif op.kind == okCsize:
        x86.emitAddImm(ctx.buf.data, dest.reg, int32(op.immVal))
      elif op.kind == okImm:
        x86.emitAddImm(ctx.buf.data, dest.reg, int32(op.immVal))
      elif op.kind == okMem:
        x86.emitAdd(ctx.buf.data, dest.reg, op.mem)
      else:
        x86.emitAdd(ctx.buf.data, dest.reg, op.reg)

  of SubX64:
    inc n
    let dest = parseDest(n, ctx, allowWidthCast = true)
    let op = parseOperand(n, ctx)

    # Type check: sub works on integers and pointers
    checkIntegerArithmetic(dest.typ, "sub", start)
    checkIntegerArithmetic(op.typ, "sub", start)
    checkArithCompatible(dest.typ, op.typ, "sub", start)  # sized ints of any width (64-bit reg)

    if dest.kind == okReg and dest.castBits != 0:
      genAluSubWidth(ctx, dest, op, saSub, start)
    elif dest.kind == okMem:
      if op.kind == okImm or op.kind == okCsize:
        x86.emitSubImm(ctx.buf.data, dest.mem, int32(op.immVal), intMemAccess(dest.typ).bits)  # SUB m, imm (sized)
      elif op.kind == okSsize:
        error("Subtracting ssize from memory not supported", n)
      elif op.kind == okMem:
        error("Cannot subtract memory from memory", n)
      else:
        x86.emitAluSizedMR(ctx.buf.data, dest.mem, op.reg, 0x28, 0x29, intMemAccess(dest.typ).bits)
    else:
      if op.kind == okSsize:
        x86.emitSubImm32(ctx.buf.data, dest.reg, 0)   # forced imm32: back-patched
        ctx.ssizePatches.add((ctx.buf.data.len - 4, int(op.immVal)))
        if ctx.inPrologue and dest.reg == x86.RSP:
          ctx.cfiStep(0, [], ssizeSlot = true)        # delta filled in at proc end
      elif op.kind == okCsize:
        x86.emitSubImm(ctx.buf.data, dest.reg, int32(op.immVal))
      elif op.kind == okImm:
        x86.emitSubImm(ctx.buf.data, dest.reg, int32(op.immVal))
        if ctx.inPrologue and dest.reg == x86.RSP:
          # the alignment-pad-only frame (`hasStackVars` false, `framePad` 8)
          ctx.cfiStep(int32(op.immVal))
      elif op.kind == okMem:
        x86.emitSub(ctx.buf.data, dest.reg, op.mem)
      else:
        checkDistinctAluRegs(dest, op, "sub", start)
        x86.emitSub(ctx.buf.data, dest.reg, op.reg)

  of MulX64:
    inc n
    let op = parseOperand(n, ctx)
    checkIntegerType(op.typ, "mul", start)
    if op.kind == okImm: error("MUL immediate not supported (use IMUL)", n)
    elif op.kind == okMem:
      x86.emitMul(ctx.buf.data, op.mem)
    else:
      x86.emitMul(ctx.buf.data, op.reg)

  of ImulX64:
    inc n
    # `(imul D S)` or the three-operand `(imul D S imm)` (D = S * imm). An
    # explicit sub-width cast on D sizes the operation like the ALU family.
    let dest = parseDest(n, ctx, allowWidthCast = true)
    let op = parseOperand(n, ctx)
    checkIntegerType(dest.typ, "imul", start)
    checkIntegerType(op.typ, "imul", start)
    if dest.kind == okMem: error("IMUL destination cannot be memory", n)
    if n.kind == IntLit:
      # (imul D S imm)
      if op.kind != okReg: error("3-operand imul source must be a register", n)
      let bits = if dest.castBits != 0: dest.castBits else: 64
      x86.emitImulImm3(ctx.buf.data, dest.reg, op.reg, int32(getInt(n)), bits)
      inc n
    elif op.kind == okImm:
      x86.emitImulImm(ctx.buf.data, dest.reg, int32(op.immVal))
    elif op.kind == okMem:
      x86.emitImul(ctx.buf.data, dest.reg, op.mem)
    else:
      x86.emitImul(ctx.buf.data, dest.reg, op.reg)

  of DivX64:
    # (div (rdx) (rax) src)
    inc n # (rdx)
    if n.kind != TagLit or n.tag != RdxTagId: error("Expected (rdx) for div", n)
    checkFixedRegFree(ctx, x86.RDX, "div", n)
    inc n

    if n.kind != TagLit or n.tag != RaxTagId: error("Expected (rax) for div", n)
    checkFixedRegFree(ctx, x86.RAX, "div", n)
    inc n

    let op = parseOperand(n, ctx)
    checkIntegerType(op.typ, "div", start)
    if op.kind == okImm: error("DIV immediate not supported", n)
    # Unsigned divide needs the high half of the dividend (RDX) zeroed.
    x86.emitXor(ctx.buf.data, x86.RDX, x86.RDX)
    if op.kind == okMem:
      x86.emitDiv(ctx.buf.data, op.mem)
    else:
      x86.emitDiv(ctx.buf.data, op.reg)

  of IdivX64:
    # (idiv (rdx) (rax) src)
    inc n # (rdx)
    if n.kind != TagLit or n.tag != RdxTagId: error("Expected (rdx) for idiv", n)
    checkFixedRegFree(ctx, x86.RDX, "idiv", n)
    inc n

    if n.kind != TagLit or n.tag != RaxTagId: error("Expected (rax) for idiv", n)
    checkFixedRegFree(ctx, x86.RAX, "idiv", n)
    inc n

    let op = parseOperand(n, ctx)
    checkIntegerType(op.typ, "idiv", start)
    if op.kind == okImm: error("IDIV immediate not supported", n)
    # Signed divide needs RAX sign-extended into RDX:RAX first.
    x86.emitCqo(ctx.buf.data)
    if op.kind == okMem:
      x86.emitIdiv(ctx.buf.data, op.mem)
    else:
      x86.emitIdiv(ctx.buf.data, op.reg)

  # Bitwise
  of AndX64:
    inc n
    let dest = parseDest(n, ctx, allowWidthCast = true)
    let op = parseOperand(n, ctx)
    checkBitwiseType(dest.typ, "and", start)
    checkBitwiseType(op.typ, "and", start)
    checkBitwiseCompatible(dest.typ, op.typ, "and", start)
    if dest.kind == okReg and dest.castBits != 0:
      genAluSubWidth(ctx, dest, op, saAnd, start)
    elif dest.kind == okMem:
      if op.kind == okImm or op.kind == okCsize:
        x86.emitAndImm(ctx.buf.data, dest.mem, int32(op.immVal), intMemAccess(dest.typ).bits)  # AND m, imm (sized)
      elif op.kind == okMem:
        error("Cannot AND memory to memory", n)
      else:
        x86.emitAluSizedMR(ctx.buf.data, dest.mem, op.reg, 0x20, 0x21, intMemAccess(dest.typ).bits)
    else:
      if op.kind == okImm:
        x86.emitAndImm(ctx.buf.data, dest.reg, int32(op.immVal))
      elif op.kind == okMem:
        x86.emitAndMem(ctx.buf.data, dest.reg, op.mem)   # and reg, [mem]
      else:
        checkDistinctAluRegs(dest, op, "and", start)
        x86.emitAnd(ctx.buf.data, dest.reg, op.reg)

  of OrX64:
    inc n
    let dest = parseDest(n, ctx, allowWidthCast = true)
    let op = parseOperand(n, ctx)
    checkBitwiseType(dest.typ, "or", start)
    checkBitwiseType(op.typ, "or", start)
    checkBitwiseCompatible(dest.typ, op.typ, "or", start)
    if dest.kind == okReg and dest.castBits != 0:
      genAluSubWidth(ctx, dest, op, saOr, start)
    elif dest.kind == okMem:
      if op.kind == okImm or op.kind == okCsize:
        x86.emitOrImm(ctx.buf.data, dest.mem, int32(op.immVal), intMemAccess(dest.typ).bits)   # OR m, imm (sized)
      elif op.kind == okMem:
        error("Cannot OR memory to memory", n)
      else:
        x86.emitAluSizedMR(ctx.buf.data, dest.mem, op.reg, 0x08, 0x09, intMemAccess(dest.typ).bits)
    else:
      if op.kind == okImm:
        x86.emitOrImm(ctx.buf.data, dest.reg, int32(op.immVal))
      elif op.kind == okMem:
        x86.emitOrMem(ctx.buf.data, dest.reg, op.mem)    # or reg, [mem]
      else:
        checkDistinctAluRegs(dest, op, "or", start)
        x86.emitOr(ctx.buf.data, dest.reg, op.reg)

  of XorX64:
    inc n
    let dest = parseDest(n, ctx, allowWidthCast = true)
    let op = parseOperand(n, ctx)
    checkBitwiseType(dest.typ, "xor", start)
    checkBitwiseType(op.typ, "xor", start)
    checkBitwiseCompatible(dest.typ, op.typ, "xor", start)
    if dest.kind == okReg and dest.castBits != 0:
      genAluSubWidth(ctx, dest, op, saXor, start)
    elif dest.kind == okMem:
      if op.kind == okImm or op.kind == okCsize:
        x86.emitXorImm(ctx.buf.data, dest.mem, int32(op.immVal), intMemAccess(dest.typ).bits)  # XOR m, imm (sized)
      elif op.kind == okMem:
        error("Cannot XOR memory to memory", n)
      else:
        x86.emitAluSizedMR(ctx.buf.data, dest.mem, op.reg, 0x30, 0x31, intMemAccess(dest.typ).bits)
    else:
      if op.kind == okImm:
        x86.emitXorImm(ctx.buf.data, dest.reg, int32(op.immVal))
      elif op.kind == okMem:
        x86.emitXorMem(ctx.buf.data, dest.reg, op.mem)   # xor reg, [mem]
      else:
        x86.emitXor(ctx.buf.data, dest.reg, op.reg)

  of ShlX64, SalX64:
    inc n
    let dest = parseDest(n, ctx, allowWidthCast = true)
    let op = parseOperand(n, ctx)
    checkBitwiseType(dest.typ, "shl", start)
    if dest.kind == okMem: error("Shift destination cannot be memory", n)
    if op.kind == okImm:
      if dest.castBits != 0:
        x86.emitShiftImmSizedR(ctx.buf.data, dest.reg, int(op.immVal), 4, dest.castBits)
      else:
        x86.emitShl(ctx.buf.data, dest.reg, int(op.immVal))
    elif op.kind == okReg and op.reg == RCX:
      if dest.castBits != 0:
        x86.emitShiftClSizedR(ctx.buf.data, dest.reg, 4, dest.castBits)
      else:
        x86.emitShlCl(ctx.buf.data, dest.reg)      # shl dest, cl
    else:
      error("Shift count must be immediate or CL", n)

  of ShrX64:
    inc n
    let dest = parseDest(n, ctx, allowWidthCast = true)
    let op = parseOperand(n, ctx)
    checkBitwiseType(dest.typ, "shr", start)
    if dest.kind == okMem: error("Shift destination cannot be memory", n)
    if op.kind == okImm:
      if dest.castBits != 0:
        x86.emitShiftImmSizedR(ctx.buf.data, dest.reg, int(op.immVal), 5, dest.castBits)
      else:
        x86.emitShr(ctx.buf.data, dest.reg, int(op.immVal))
    elif op.kind == okReg and op.reg == RCX:
      if dest.castBits != 0:
        x86.emitShiftClSizedR(ctx.buf.data, dest.reg, 5, dest.castBits)
      else:
        x86.emitShrCl(ctx.buf.data, dest.reg)      # shr dest, cl
    else:
      error("Shift count must be immediate or CL", n)

  of SarX64:
    inc n
    let dest = parseDest(n, ctx, allowWidthCast = true)
    let op = parseOperand(n, ctx)
    checkBitwiseType(dest.typ, "sar", start)
    if dest.kind == okMem: error("Shift destination cannot be memory", n)
    if op.kind == okImm:
      if dest.castBits != 0:
        x86.emitShiftImmSizedR(ctx.buf.data, dest.reg, int(op.immVal), 7, dest.castBits)
      else:
        x86.emitSar(ctx.buf.data, dest.reg, int(op.immVal))
    elif op.kind == okReg and op.reg == RCX:
      if dest.castBits != 0:
        x86.emitShiftClSizedR(ctx.buf.data, dest.reg, 7, dest.castBits)
      else:
        x86.emitSarCl(ctx.buf.data, dest.reg)      # sar dest, cl
    else:
      error("Shift count must be immediate or CL", n)

  # Unary
  of IncX64:
    inc n
    let op = parseDest(n, ctx) # Dest/Src same
    checkIntegerArithmetic(op.typ, "inc", start)
    if op.kind == okMem: error("INC memory not supported yet", n)
    x86.emitInc(ctx.buf.data, op.reg)

  of DecX64:
    inc n
    let op = parseDest(n, ctx)
    checkIntegerArithmetic(op.typ, "dec", start)
    if op.kind == okMem: error("DEC memory not supported yet", n)
    x86.emitDec(ctx.buf.data, op.reg)

  of NegX64:
    inc n
    let op = parseDest(n, ctx, allowWidthCast = true)
    checkIntegerArithmetic(op.typ, "neg", start)
    if op.kind == okMem: error("NEG memory not supported yet", n)
    if op.castBits != 0:
      x86.emitUnarySizedR(ctx.buf.data, op.reg, 3, op.castBits)   # NEG = /3
    else:
      x86.emitNeg(ctx.buf.data, op.reg)

  of NotX64:
    inc n
    let op = parseDest(n, ctx, allowWidthCast = true)
    checkBitwiseType(op.typ, "not", start)
    if op.kind == okMem: error("NOT memory not supported yet", n)
    if op.castBits != 0:
      x86.emitUnarySizedR(ctx.buf.data, op.reg, 2, op.castBits)   # NOT = /2
    else:
      x86.emitNot(ctx.buf.data, op.reg)

  # Rotates: `(rol D S)` etc. D is a register, S an immediate count (the CL
  # form has no emitter yet). Mirrors the shift dispatch above.
  of RolX64, RorX64, RclX64, RcrX64:
    let name = $instTag
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    checkBitwiseType(dest.typ, name, start)
    if dest.kind == okMem: error("Rotate destination cannot be memory", n)
    if op.kind == okReg and op.reg == RCX and instTag in {RolX64, RorX64}:
      # Rotate by CL — same 0xD3 group as the shifts, digits /0 and /1.
      x86.emitShiftCl(ctx.buf.data, dest.reg, if instTag == RolX64: 0 else: 1)
    elif op.kind != okImm:
      error("Rotate count must be immediate or CL", n)
    else:
      let count = int(op.immVal)
      case instTag
      of RolX64: x86.emitRol(ctx.buf.data, dest.reg, count)
      of RorX64: x86.emitRor(ctx.buf.data, dest.reg, count)
      of RclX64: x86.emitRcl(ctx.buf.data, dest.reg, count)
      else:      x86.emitRcr(ctx.buf.data, dest.reg, count)

  # Bit scan: `(bsf D S)` / `(bsr D S)` — D and S are both registers.
  of BsfX64, BsrX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    checkBitwiseType(dest.typ, $instTag, start)
    if dest.kind != okReg: error("Bit-scan destination must be a register", n)
    if op.kind != okReg: error("Bit-scan source must be a register", n)
    if instTag == BsfX64:
      x86.emitBsf(ctx.buf.data, dest.reg, op.reg)
    else:
      x86.emitBsr(ctx.buf.data, dest.reg, op.reg)

  # Population count: `(popcnt D S N)`. `N` (32 or 64) is the operand size, given
  # EXPLICITLY rather than inferred from the operand types — the destination of a
  # bit-counting instruction is a small count whose declared type says nothing
  # about the width the instruction must run at. Same convention as `(bswap D N)`.
  of PopcntX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    checkBitwiseType(dest.typ, $instTag, start)
    checkBitwiseType(op.typ, $instTag, start)
    if dest.kind != okReg: error("popcnt destination must be a register", n)
    if op.kind != okReg: error("popcnt source must be a register", n)
    if n.kind != IntLit: error("popcnt requires a width operand (32 or 64)", n)
    let bits = int(getInt(n)); inc n
    if bits != 32 and bits != 64: error("popcnt width must be 32 or 64", n)
    x86.emitPopcnt(ctx.buf.data, dest.reg, op.reg, bits)

  # Byte swap: `(bswap D bits)` — D is a register reversed IN PLACE; `bits` is 32 or 64
  # (selects the operand size). Used to lower `__builtin_bswap32/64`.
  of BswapX64:
    inc n
    let dest = parseDest(n, ctx)
    if dest.kind != okReg: error("bswap destination must be a register", n)
    if n.kind != IntLit: error("bswap requires a width operand (32 or 64)", n)
    let bits = int(getInt(n)); inc n
    if bits != 32 and bits != 64: error("bswap width must be 32 or 64", n)
    x86.emitBswap(ctx.buf.data, dest.reg, bits)

  # Bit test family: `(bt D S)` etc. D is a register, S an immediate bit
  # index or a REGISTER bit index (taken modulo the operand width). An
  # explicit sub-width cast on D sizes the operation like the ALU family.
  of BtX64, BtsX64, BtrX64, BtcX64:
    inc n
    let dest = parseDest(n, ctx, allowWidthCast = true)
    let op = parseOperand(n, ctx)
    checkBitwiseType(dest.typ, $instTag, start)
    if dest.kind != okReg: error("Bit-test destination must be a register", n)
    if op.kind == okReg:
      let bits = if dest.castBits != 0: dest.castBits else: 64
      if op.castBits != 0 and op.castBits != bits:
        error("sub-width operand widths disagree: " & $bits & " vs " &
              $op.castBits, n)
      let opc = case instTag
                of BtX64: 0xA3'u8
                of BtsX64: 0xAB'u8
                of BtrX64: 0xB3'u8
                else: 0xBB'u8
      x86.emitBtxRR(ctx.buf.data, dest.reg, op.reg, opc, bits)
    elif op.kind != okImm:
      error("Bit-test bit index must be immediate or a register", n)
    else:
      let bit = int(op.immVal)
      case instTag
      of BtX64:  x86.emitBt(ctx.buf.data, dest.reg, bit)
      of BtsX64: x86.emitBts(ctx.buf.data, dest.reg, bit)
      of BtrX64: x86.emitBtr(ctx.buf.data, dest.reg, bit)
      else:      x86.emitBtc(ctx.buf.data, dest.reg, bit)

  # Comparison
  of CmpX64:
    inc n
    let dest = parseDest(n, ctx, allowWidthCast = true) # Actually just operand 1
    let op = parseOperand(n, ctx)
    # Comparisons work on integers, pointers, and bool (the "if bool" test).
    checkComparable(dest.typ, "cmp", start)
    checkComparable(op.typ, "cmp", start)
    checkCmpCompatible(dest.typ, op.typ, start)
    if dest.kind == okReg and dest.castBits != 0:
      genAluSubWidth(ctx, dest, op, saCmp, start)
    elif dest.kind == okMem:
      if op.kind == okImm:
        x86.emitCmpImm(ctx.buf.data, dest.mem, int32(op.immVal), intMemAccess(dest.typ).bits)  # CMP m, imm (sized)
      elif op.kind == okMem:
        error("Cannot compare memory with memory", n)
      else:
        # CMP mem, reg — sized by the memory operand's type so a byte/word/dword
        # compare does not over-read adjacent bytes (the `cmp r/m64,r64` default read
        # 8 bytes of a `char` element and always mismatched).
        x86.emitCmpSized(ctx.buf.data, dest.mem, op.reg, intMemAccess(dest.typ).bits)
    else:
      if op.kind == okImm:
        x86.emitCmpImm(ctx.buf.data, dest.reg, int32(op.immVal))
      elif op.kind == okMem:
        x86.emitCmpSized(ctx.buf.data, dest.reg, op.mem, intMemAccess(op.typ).bits)
      else:
        x86.emitCmp(ctx.buf.data, dest.reg, op.reg)

  # Width extension: `(movzx D S N)` / `(movsx D S N)`. Three-address like the a64
  # `(clz D S N)` — `N` (8/16/32) is the SOURCE width, given explicitly because the
  # declared type of a register says nothing about how many of its bits are the
  # value. The register-source counterpart of the sized load `(mov D (mem …))`
  # already performs.
  of MovzxX64, MovsxX64:
    let mnemonic = $instTag
    let signed = instTag == MovsxX64
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    # `checkComparable` for the same reason as `test`: a bool IS an 8-bit value a
    # zero-extension is meaningful on, and `canDoBitwiseOps` excludes it.
    checkComparable(dest.typ, mnemonic, start)
    checkComparable(op.typ, mnemonic, start)
    if dest.kind != okReg: error(mnemonic & " destination must be a register", n)
    if op.kind != okReg: error(mnemonic & " source must be a register", n)
    if n.kind != IntLit: error(mnemonic & " requires a width operand (8, 16 or 32)", n)
    let bits = int(getInt(n)); inc n
    if bits notin {8, 16, 32}: error(mnemonic & " width must be 8, 16 or 32", n)
    x86.emitRegExt(ctx.buf.data, dest.reg, op.reg, bits, signed)
    # The destination is freshly written, so an earlier call's clobber no longer
    # applies — same rule as `mov`/`lea` (see genMovX64).
    ctx.clobbered.excl(dest.reg)

  of TestX64:
    inc n
    let dest = parseDest(n, ctx, allowWidthCast = true)
    let op = parseOperand(n, ctx)
    # `checkComparable`, not `checkBitwiseType`: `test r, r` is the canonical
    # zero-test and so has exactly `cmp`'s operand domain — a bool ("is this flag
    # set") and a pointer ("is this nil") are both legitimate, and `cmp x, 0`
    # already accepts them. `test` only reads its operands to set flags.
    checkComparable(dest.typ, "test", start)
    checkComparable(op.typ, "test", start)
    checkCmpCompatible(dest.typ, op.typ, start)
    if dest.kind == okReg and dest.castBits != 0:
      genAluSubWidth(ctx, dest, op, saTest, start)
    elif dest.kind == okMem:
      if op.kind == okImm:
        # TEST mem, imm — 0xF6/0xF7 /0, sized by the memory operand's type.
        x86.emitTestImmSizedM(ctx.buf.data, dest.mem, int32(op.immVal),
                              intMemAccess(dest.typ).bits)
      elif op.kind == okReg:
        # TEST mem, reg — sized by the memory operand's type (0x84/0x85 MR).
        x86.emitAluSizedMR(ctx.buf.data, dest.mem, op.reg, 0x84, 0x85,
                           intMemAccess(dest.typ).bits)
      else:
        error("TEST memory requires a register or immediate source", n)
    elif op.kind == okImm:
      # emitTestImm
      error("TEST immediate not supported yet", n)
    elif op.kind == okMem:
      error("TEST with memory operand not supported yet", n)
    else:
      x86.emitTest(ctx.buf.data, dest.reg, op.reg)

  # Conditional Sets
  of SeteX64, SetzX64:
    inc n
    let dest = parseDest(n, ctx)
    if dest.kind == okMem: error("SETcc memory not supported yet", n)
    x86.emitSete(ctx.buf.data, dest.reg)

  of SetneX64, SetnzX64:
    inc n
    let dest = parseDest(n, ctx)
    if dest.kind == okMem: error("SETcc memory not supported yet", n)
    x86.emitSetne(ctx.buf.data, dest.reg)

  of SetaX64, SetnbeX64:
    inc n
    let dest = parseDest(n, ctx)
    if dest.kind == okMem: error("SETcc memory not supported yet", n)
    x86.emitSeta(ctx.buf.data, dest.reg)

  of SetaeX64, SetnbX64, SetncX64:
    inc n
    let dest = parseDest(n, ctx)
    if dest.kind == okMem: error("SETcc memory not supported yet", n)
    x86.emitSetae(ctx.buf.data, dest.reg)

  of SetbX64, SetnaeX64, SetcX64:
    inc n
    let dest = parseDest(n, ctx)
    if dest.kind == okMem: error("SETcc memory not supported yet", n)
    x86.emitSetb(ctx.buf.data, dest.reg)
  of SetbeX64, SetnaX64:
    inc n
    let dest = parseDest(n, ctx)
    if dest.kind == okMem: error("SETcc memory not supported yet", n)
    x86.emitSetbe(ctx.buf.data, dest.reg)

  of SetgX64, SetnleX64:
    inc n
    let dest = parseDest(n, ctx)
    if dest.kind == okMem: error("SETcc memory not supported yet", n)
    x86.emitSetg(ctx.buf.data, dest.reg)

  of SetgeX64, SetnlX64:
    inc n
    let dest = parseDest(n, ctx)
    if dest.kind == okMem: error("SETcc memory not supported yet", n)
    x86.emitSetge(ctx.buf.data, dest.reg)
  of SetlX64, SetngeX64:
    inc n
    let dest = parseDest(n, ctx)
    if dest.kind == okMem: error("SETcc memory not supported yet", n)
    x86.emitSetl(ctx.buf.data, dest.reg)

  of SetleX64, SetngX64:
    inc n
    let dest = parseDest(n, ctx)
    if dest.kind == okMem: error("SETcc memory not supported yet", n)
    x86.emitSetle(ctx.buf.data, dest.reg)

  of SetoX64:
    inc n
    let dest = parseDest(n, ctx)
    if dest.kind == okMem: error("SETcc memory not supported yet", n)
    x86.emitSeto(ctx.buf.data, dest.reg)

  of SetsX64:
    inc n
    let dest = parseDest(n, ctx)
    if dest.kind == okMem: error("SETcc memory not supported yet", n)
    x86.emitSets(ctx.buf.data, dest.reg)

  of SetpX64:
    inc n
    let dest = parseDest(n, ctx)
    if dest.kind == okMem: error("SETcc memory not supported yet", n)
    x86.emitSetp(ctx.buf.data, dest.reg)
  # Conditional moves
  of CmoveX64, CmovzX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.kind == okMem: error("CMOV destination must be a register", n)
    if op.kind == okImm: error("CMOV immediate not supported", n)
    if op.kind == okMem: x86.emitCmove(ctx.buf.data, dest.reg, op.mem)
    else: x86.emitCmove(ctx.buf.data, dest.reg, op.reg)

  of CmovneX64, CmovnzX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.kind == okMem: error("CMOV destination must be a register", n)
    if op.kind == okImm: error("CMOV immediate not supported", n)
    if op.kind == okMem: x86.emitCmovne(ctx.buf.data, dest.reg, op.mem)
    else: x86.emitCmovne(ctx.buf.data, dest.reg, op.reg)

  of CmovaX64, CmovnbeX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.kind == okMem: error("CMOV destination must be a register", n)
    if op.kind == okImm: error("CMOV immediate not supported", n)
    if op.kind == okMem: x86.emitCmova(ctx.buf.data, dest.reg, op.mem)
    else: x86.emitCmova(ctx.buf.data, dest.reg, op.reg)

  of CmovaeX64, CmovnbX64, CmovncX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.kind == okMem: error("CMOV destination must be a register", n)
    if op.kind == okImm: error("CMOV immediate not supported", n)
    if op.kind == okMem: x86.emitCmovae(ctx.buf.data, dest.reg, op.mem)
    else: x86.emitCmovae(ctx.buf.data, dest.reg, op.reg)

  of CmovbX64, CmovnaeX64, CmovcX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.kind == okMem: error("CMOV destination must be a register", n)
    if op.kind == okImm: error("CMOV immediate not supported", n)
    if op.kind == okMem: x86.emitCmovb(ctx.buf.data, dest.reg, op.mem)
    else: x86.emitCmovb(ctx.buf.data, dest.reg, op.reg)

  of CmovbeX64, CmovnaX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.kind == okMem: error("CMOV destination must be a register", n)
    if op.kind == okImm: error("CMOV immediate not supported", n)
    if op.kind == okMem: x86.emitCmovbe(ctx.buf.data, dest.reg, op.mem)
    else: x86.emitCmovbe(ctx.buf.data, dest.reg, op.reg)

  of CmovgX64, CmovnleX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.kind == okMem: error("CMOV destination must be a register", n)
    if op.kind == okImm: error("CMOV immediate not supported", n)
    if op.kind == okMem: x86.emitCmovg(ctx.buf.data, dest.reg, op.mem)
    else: x86.emitCmovg(ctx.buf.data, dest.reg, op.reg)

  of CmovgeX64, CmovnlX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.kind == okMem: error("CMOV destination must be a register", n)
    if op.kind == okImm: error("CMOV immediate not supported", n)
    if op.kind == okMem: x86.emitCmovge(ctx.buf.data, dest.reg, op.mem)
    else: x86.emitCmovge(ctx.buf.data, dest.reg, op.reg)

  of CmovlX64, CmovngeX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.kind == okMem: error("CMOV destination must be a register", n)
    if op.kind == okImm: error("CMOV immediate not supported", n)
    if op.kind == okMem: x86.emitCmovl(ctx.buf.data, dest.reg, op.mem)
    else: x86.emitCmovl(ctx.buf.data, dest.reg, op.reg)

  of CmovleX64, CmovngX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.kind == okMem: error("CMOV destination must be a register", n)
    if op.kind == okImm: error("CMOV immediate not supported", n)
    if op.kind == okMem: x86.emitCmovle(ctx.buf.data, dest.reg, op.mem)
    else: x86.emitCmovle(ctx.buf.data, dest.reg, op.reg)

  of CmovoX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.kind == okMem: error("CMOV destination must be a register", n)
    if op.kind == okImm: error("CMOV immediate not supported", n)
    if op.kind == okMem: x86.emitCmovo(ctx.buf.data, dest.reg, op.mem)
    else: x86.emitCmovo(ctx.buf.data, dest.reg, op.reg)

  of CmovsX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.kind == okMem: error("CMOV destination must be a register", n)
    if op.kind == okImm: error("CMOV immediate not supported", n)
    if op.kind == okMem: x86.emitCmovs(ctx.buf.data, dest.reg, op.mem)
    else: x86.emitCmovs(ctx.buf.data, dest.reg, op.reg)

  of CmovpX64, CmovpeX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.kind == okMem: error("CMOV destination must be a register", n)
    if op.kind == okImm: error("CMOV immediate not supported", n)
    if op.kind == okMem: x86.emitCmovp(ctx.buf.data, dest.reg, op.mem)
    else: x86.emitCmovp(ctx.buf.data, dest.reg, op.reg)

  of CmovnpX64, CmovpoX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.kind == okMem: error("CMOV destination must be a register", n)
    if op.kind == okImm: error("CMOV immediate not supported", n)
    if op.kind == okMem: x86.emitCmovnp(ctx.buf.data, dest.reg, op.mem)
    else: x86.emitCmovnp(ctx.buf.data, dest.reg, op.reg)

  of CmovnsX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.kind == okMem: error("CMOV destination must be a register", n)
    if op.kind == okImm: error("CMOV immediate not supported", n)
    if op.kind == okMem: x86.emitCmovns(ctx.buf.data, dest.reg, op.mem)
    else: x86.emitCmovns(ctx.buf.data, dest.reg, op.reg)

  of CmovnoX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    if dest.kind == okMem: error("CMOV destination must be a register", n)
    if op.kind == okImm: error("CMOV immediate not supported", n)
    if op.kind == okMem: x86.emitCmovno(ctx.buf.data, dest.reg, op.mem)
    else: x86.emitCmovno(ctx.buf.data, dest.reg, op.reg)
  # Stack
  of PushX64:
    inc n
    let op = parseOperand(n, ctx)
    if op.kind == okImm:
      x86.emitPush(ctx.buf.data, int32(op.immVal))
    elif op.kind == okMem:
      error("PUSH memory not supported yet", n)
    else:
      x86.emitPush(ctx.buf.data, op.reg)
      if ctx.inPrologue:
        # A callee-saved register saved by the prologue: the CFA moves 8 further
        # from SP and the register now lives at the new bottom of the frame.
        ctx.cfiStep(8, [int32(ord(op.reg))])

  of PopX64:
    inc n
    let dest = parseDest(n, ctx)
    if dest.kind == okMem:
      error("POP memory not supported yet", n)
    else:
      x86.emitPop(ctx.buf.data, dest.reg)

  of SyscallX64:
    if ctx.inCall and ctx.callContext.isSyscall:
      genSyscallMarkerX64(n, ctx)   # `(syscall)` as the prepare invocation marker
    else:
      inc n
      x86.emitSyscall(ctx.buf.data)  # a raw `syscall` (e.g. the entry's exit path)
  of LeaX64:
    # (lea dest base-reg offset) or (lea dest label). The destination is a
    # register or a named register local. `lea` *defines* its destination, so a
    # raw register node is accepted whether or not it is bound (unlike a use,
    # which parseDest would reject); a named local resolves to its register.
    inc n
    var dest: x86.Register
    if n.kind == Symbol:
      let name = getSym(n)
      let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
      # A register-homed local OR param is a legal `lea` destination: `lea` DEFINES it,
      # and a param kept in its incoming arg register (e.g. `lea rdi, [rdi+off]` when the
      # param is dead afterwards) is exactly the address-of-a-field marshalling arkham
      # emits. Match the `{skVar, skParam}` convention used by every other operand path.
      if sym != nil and sym.kind in {skVar, skParam} and sym.reg != InvalidTagId:
        dest = tagToRegister(sym.reg, n)
        ctx.clobbered.excl(dest)            # writing it makes it valid again
        inc n
      else:
        error("lea destination must be a register or register-bound local", n)
    elif n.kind == TagLit and rawTagIsX64Reg(n.tag):
      dest = parseRegister(n)
    else:
      error("lea destination must be a register", n)

    # Check if next is a label or register
    var baseReg: x86.Register
    if n.kind == TagLit and n.tag == LabTagId:
      # (lea dest (lab label)) - RIP-relative address
      inc n
      if n.kind != Symbol: error("Expected label name", n)
      let name = getSym(n)
      let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
      if sym == nil or sym.kind != skLabel: error("Unknown label: " & name, n)
      if sym == ctx.traceSym: ctx.traceUsed = true   # emit the table (appendTraceTable)
      inc n
      x86.emitLea(ctx.buf, dest, LabelId(sym.offset))
    elif leaRegBase(n, ctx, baseReg):
      # (lea dest base-reg offset) - explicit addressing. `base-reg` is a raw `(reg)`
      # or a register-bound local name (a `rebind`'d scratch temp).
      var displacement: int32 = 0

      # Parse offset - can be integer or stack variable name
      if n.kind == IntLit:
        displacement = int32(getInt(n))
        inc n
      elif n.kind == Symbol:
        let offsetName = getSym(n)
        let offsetSym = lookupWithAutoImport(ctx, ctx.scope, offsetName, n)
        if offsetSym != nil and offsetSym.kind == skTvar:
          # `lea dest, (fsbase) tvar` ⇒ dest = fsbase + tvar.offset = &tvar. A
          # thread-local has no link-time address (it lives at FS_base + offset);
          # nifasm owns the offset, the caller supplies the FS-base register, and
          # the offset folds into the lea displacement — no pointer arithmetic.
          displacement = int32(offsetSym.offset)
        elif offsetSym != nil and (offsetSym.kind == skVar or offsetSym.kind == skParam) and offsetSym.typ.isOnStack:
          displacement = int32(offsetSym.offset)
        else:
          error("Expected stack variable, thread-local, or integer offset in lea", n)
        inc n
      else:
        error("Expected offset (integer or stack variable) in lea", n)

      let mem = x86.MemoryOperand(
        base: baseReg,
        displacement: displacement,
        hasIndex: false
      )
      x86.emitLea(ctx.buf.data, dest, mem)
    else:
      # Try parsing as a label operand (rodata, gvar, etc.) or an addressing
      # expression — `(at …)` / `(dot …)` / `(mem …)` all parse to an `okMem`
      # operand carrying a full base+index*scale+displacement, which `lea`
      # materializes as an address (matching the AArch64 backend, whose `lea`
      # accepts the same forms). This is how arkham takes the address of an array
      # element or aggregate field on x86-64.
      let op = parseOperand(n, ctx)
      if op.gvarSym != nil:
        # Global in .bss (a different segment): emit a placeholder RIP-relative lea
        # and record the site; writeElf patches the disp32 against the .bss vaddr.
        let pos = x86.emitLeaRipPlaceholder(ctx.buf, dest)
        ctx.gvarSites.add (pos, op.gvarSym)
      elif op.kind == okLabel:
        x86.emitLea(ctx.buf, dest, op.label)
      elif op.kind == okMem:
        # `lea dest, [dest]` is a no-op. It is not incidental: the 3-operand
        # `(at base index scratch)` form computes the address INTO the scratch and
        # hands back `okMem{base: scratch}`, and arkham deliberately passes the
        # consuming instruction's destination as that scratch (`prematLval2`'s
        # `hint`, so the stride needs no third register). The address is therefore
        # already in `dest` by the time we get here.
        if not (op.mem.base == dest and not op.mem.hasIndex and
                op.mem.displacement == 0):
          x86.emitLea(ctx.buf.data, dest, op.mem)
      else:
        error("lea requires an address expression (base-reg offset, mem, dot, at, or label)", n)
  of JmpX64:
    inc n
    if ctx.lenient and n.kind == Symbol:
      # Lenient tail call: `(jmp P)` straight to another proc's entry.
      let tsym = lookupWithAutoImport(ctx, ctx.scope, getSym(n), n)
      if tsym != nil and tsym.kind == skProc:
        inc n
        var labId: LabelId
        if tsym.offset == -1:
          labId = ctx.buf.createLabel()
          tsym.offset = int(labId)
        else:
          labId = LabelId(tsym.offset)
        ctx.buf.emitJmp(labId)
        return
    let op = parseOperand(n, ctx)
    if op.kind == okMem:
      error("JMP memory not supported yet", n)
    elif op.label != LabelId(0) or op.typ.kind == UIntT: # Label check
      # op.label is set if it was a label operand
      if op.typ.kind == UIntT: # Label address
        checkForwardJump(ctx, op.label, n)
        x86.emitJmp(ctx.buf, op.label)
      else:
        x86.emitJmpReg(ctx.buf.data, op.reg)
    else:
      x86.emitJmpReg(ctx.buf.data, op.reg) # Default to reg jump if not label?
  of JeX64, JzX64:
    inc n
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    checkForwardJump(ctx, op.label, n)
    x86.emitJe(ctx.buf, op.label)
  of JneX64, JnzX64:
    inc n
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    checkForwardJump(ctx, op.label, n)
    x86.emitJne(ctx.buf, op.label)
  of JgX64:
    inc n
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    checkForwardJump(ctx, op.label, n)
    x86.emitJg(ctx.buf, op.label)
  of JgeX64:
    inc n
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    checkForwardJump(ctx, op.label, n)
    x86.emitJge(ctx.buf, op.label)
  of JlX64:
    inc n
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    checkForwardJump(ctx, op.label, n)
    x86.emitJl(ctx.buf, op.label)
  of JleX64:
    inc n
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    checkForwardJump(ctx, op.label, n)
    x86.emitJle(ctx.buf, op.label)
  of JaX64:
    inc n
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    checkForwardJump(ctx, op.label, n)
    x86.emitJa(ctx.buf, op.label)
  of JaeX64:
    inc n
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    checkForwardJump(ctx, op.label, n)
    x86.emitJae(ctx.buf, op.label)
  of JbX64:
    inc n
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    checkForwardJump(ctx, op.label, n)
    x86.emitJb(ctx.buf, op.label)
  of JbeX64:
    inc n
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    checkForwardJump(ctx, op.label, n)
    x86.emitJbe(ctx.buf, op.label)
  of JoX64:
    inc n
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    checkForwardJump(ctx, op.label, n)
    x86.emitJo(ctx.buf, op.label)
  of JnoX64:
    inc n
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    checkForwardJump(ctx, op.label, n)
    x86.emitJno(ctx.buf, op.label)
  of JsX64:
    inc n
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    checkForwardJump(ctx, op.label, n)
    x86.emitJs(ctx.buf, op.label)
  of JnsX64:
    inc n
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    checkForwardJump(ctx, op.label, n)
    x86.emitJns(ctx.buf, op.label)
  of JpX64:
    # PF=1. After `comisd`/`comiss` that is the UNORDERED result (an operand was
    # NaN), which is how a float comparison tells "equal" from "either is NaN" —
    # ZF alone cannot, since unordered sets ZF too.
    inc n
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    checkForwardJump(ctx, op.label, n)
    x86.emitJp(ctx.buf, op.label)
  of JngX64:
    inc n
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    checkForwardJump(ctx, op.label, n)
    x86.emitJle(ctx.buf, op.label)
  of JngeX64:
    inc n
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    checkForwardJump(ctx, op.label, n)
    x86.emitJl(ctx.buf, op.label)
  of JnaX64:
    inc n
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    checkForwardJump(ctx, op.label, n)
    x86.emitJbe(ctx.buf, op.label)
  of JnaeX64:
    inc n
    let op = parseOperand(n, ctx)
    if op.typ.kind != UIntT: error("Jump target must be label", n)
    checkForwardJump(ctx, op.label, n)
    x86.emitJb(ctx.buf, op.label)
  of NopX64:
    inc n
    x86.emitNop(ctx.buf.data)
  of CasejmpX64:
    # The one escaped arm that consumes the WHOLE node itself (`n.into`) rather
    # than walking operands, so it wants the head back, not the step-over above.
    n = start
    genCasejmpX64(n, ctx)
  of RepstosbX64, RepstosqX64:
    # `rep stos`: fills `rcx` units at `[rdi]` with al/rax, advancing rdi and
    # zeroing rcx — record those clobbers like the `rep movs` family below.
    inc n
    ctx.clobbered.incl {x86.RDI, x86.RCX}
    if instTag == RepstosbX64: x86.emitRepStosb(ctx.buf.data)
    else:                      x86.emitRepStosq(ctx.buf.data)
  of RepmovsbX64, RepmovswX64, RepmovsdX64, RepmovsqX64:
    # The `rep movs` family names NONE of its operands in the tree: it copies `rcx`
    # units from `[rsi]` to `[rdi]`, advancing both pointers and leaving `rcx` at 0.
    # Record that clobber explicitly — without it a later read of a local homed in
    # rdi/rsi/rcx would silently see a destroyed value instead of raising here.
    # (DF is 0 throughout: SysV guarantees it clear at entry and at every call, and
    # nothing in this assembler emits `std`, so `movs` always steps upward.)
    inc n
    ctx.clobbered.incl {x86.RDI, x86.RSI, x86.RCX}
    if instTag == RepmovsbX64:   x86.emitRepMovsb(ctx.buf.data)
    elif instTag == RepmovswX64: x86.emitRepMovsw(ctx.buf.data)
    elif instTag == RepmovsdX64: x86.emitRepMovsd(ctx.buf.data)
    else:                        x86.emitRepMovsq(ctx.buf.data)
  of RetX64:
    inc n
    x86.emitRet(ctx.buf.data)
  of LabX64:
    # (lab :label)
    inc n
    if n.kind != SymbolDef: error("Expected label name", n)
    let name = symName(n)
    let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
    # Label might not be defined yet if this is inside a proc body?
    # No, Pass 1 handles types/procs. Labels are local to procs?
    # Labels are typically declared in Pass 1?
    # nifasm: labels can be defined inline.
    # We need to define the label symbol in the scope if not exists, or look it up.
    # If it's a forward jump, we need to have created it.
    # Pass 1 does not scan bodies for labels.
    # So we create it here if missing.
    if sym == nil:
      let labId = ctx.buf.createLabel()
      ctx.scope.define(Symbol(name: ctx.symIdOf(name), kind: skLabel, offset: int(labId)))
      ctx.buf.defineLabel(labId)
      ctx.definedLabels.incl int(labId)
    elif sym.kind == skLabel:
      if sym.offset == -1:
        let labId = ctx.buf.createLabel()
        sym.offset = int(labId)
        ctx.buf.defineLabel(labId)
        ctx.definedLabels.incl int(labId)
      else:
        ctx.buf.defineLabel(LabelId(sym.offset))
        ctx.definedLabels.incl sym.offset
    else:
      error("Symbol is not a label", n)
    inc n

  of MovapdX64:
    # `(movapd D S)`: aligned 128-bit float move, one side may be memory —
    # same shape as movdqu; the aligned form faults on a misaligned address.
    inc n
    if isXmmOperand(n, ctx):
      let d = parseXmmOperand(n, ctx)
      if isXmmOperand(n, ctx):
        let s = parseXmmOperand(n, ctx)
        x86.emitMovapd(ctx.buf.data, d, s)
      else:
        let s = parseOperand(n, ctx)
        if s.kind != okMem: error("movapd source must be xmm or memory", n)
        x86.emitMovapdLoad(ctx.buf.data, d, s.mem)
    else:
      let d = parseOperand(n, ctx)
      if d.kind != okMem: error("movapd destination must be xmm or memory", n)
      let s = parseXmmOperand(n, ctx)
      x86.emitMovapdStore(ctx.buf.data, d.mem, s)
  of MovsdX64, MovssX64:
    # `(movsd D S)`: a scalar-float move where one side may be memory:
    #   (movsd (xmmD) (xmmS))   reg→reg ;  (movsd (xmmD) (mem …))  load
    #   (movsd (mem …) (xmmS))  store
    let isD = instTag == MovsdX64
    inc n
    if isXmmOperand(n, ctx):
      let d = parseXmmOperand(n, ctx)
      if isXmmOperand(n, ctx):
        let s = parseXmmOperand(n, ctx)
        if isD: x86.emitMovsd(ctx.buf.data, d, s)
        else:   x86.emitMovss(ctx.buf.data, d, s)
      else:
        let s = parseOperand(n, ctx)
        if s.kind != okMem: error("movsd/movss source must be xmm or memory", n)
        if isD: x86.emitMovsdLoad(ctx.buf.data, d, s.mem)
        else:   x86.emitMovssLoad(ctx.buf.data, d, s.mem)
    else:
      let d = parseOperand(n, ctx)
      if d.kind != okMem: error("movsd/movss destination must be xmm or memory", n)
      let s = parseXmmOperand(n, ctx)
      if isD: x86.emitMovsdStore(ctx.buf.data, d.mem, s)
      else:   x86.emitMovssStore(ctx.buf.data, d.mem, s)

  of MovdquX64:
    # `(movdqu D S)`: unaligned 128-bit move, one side may be memory —
    #   (movdqu (xmmD) (xmmS)) reg→reg; (movdqu (xmmD) (mem …)) load;
    #   (movdqu (mem …) (xmmS)) store.
    # The access is inherently 16 bytes: the mem operand's declared scalar type is
    # NOT consulted (the hardware instruction has no operand-size field either), so
    # a word-typed `(cast (u 64) (mem …))` operand is fine — the aggregate copier
    # addresses its 16-byte chunks with the same operand shapes as its word moves.
    inc n
    if isXmmOperand(n, ctx):
      let d = parseXmmOperand(n, ctx)
      if isXmmOperand(n, ctx):
        let s = parseXmmOperand(n, ctx)
        x86.emitMovdqu(ctx.buf.data, d, s)
      else:
        let s = parseOperand(n, ctx)
        if s.kind != okMem: error("movdqu source must be xmm or memory", n)
        x86.emitMovdquLoad(ctx.buf.data, d, s.mem)
    else:
      let d = parseOperand(n, ctx)
      if d.kind != okMem: error("movdqu destination must be xmm or memory", n)
      let s = parseXmmOperand(n, ctx)
      x86.emitMovdquStore(ctx.buf.data, d.mem, s)

  of PunpcklqdqX64:
    # `(punpcklqdq D S)`: D = [D.lo, S.lo] — xmm registers only. gcc uses the
    # self form to broadcast a quadword before a 16-byte store.
    inc n
    let d = parseXmmOperand(n, ctx)
    let s = parseXmmOperand(n, ctx)
    x86.emitPunpcklqdq(ctx.buf.data, d, s)

  of MovupdX64, MovupsX64:
    # `(movupd D S)` / `(movups D S)`: unaligned 128-bit float move, one side may
    # be memory. Like `movdqu`, the access is inherently 16 bytes and the mem
    # operand's declared scalar type is not consulted.
    let packedSingle = instTag == MovupsX64
    inc n
    if isXmmOperand(n, ctx):
      let d = parseXmmOperand(n, ctx)
      if isXmmOperand(n, ctx):
        let s = parseXmmOperand(n, ctx)
        if packedSingle: x86.emitMovups(ctx.buf.data, d, s)
        else: x86.emitMovupd(ctx.buf.data, d, s)
      else:
        let s = parseOperand(n, ctx)
        if s.kind != okMem: error("movupd/movups source must be xmm or memory", n)
        if packedSingle: x86.emitMovupsLoad(ctx.buf.data, d, s.mem)
        else: x86.emitMovupdLoad(ctx.buf.data, d, s.mem)
    else:
      let d = parseOperand(n, ctx)
      if d.kind != okMem: error("movupd/movups destination must be xmm or memory", n)
      let s = parseXmmOperand(n, ctx)
      if packedSingle: x86.emitMovupsStore(ctx.buf.data, d.mem, s)
      else: x86.emitMovupdStore(ctx.buf.data, d.mem, s)

  of AddpdX64, SubpdX64, MulpdX64, AddpsX64, SubpsX64, MulpsX64:
    # Packed float ALU — xmm registers only.
    inc n
    let d = parseXmmOperand(n, ctx)
    let s = parseXmmOperand(n, ctx)
    case instTag
    of AddpdX64: x86.emitAddpd(ctx.buf.data, d, s)
    of SubpdX64: x86.emitSubpd(ctx.buf.data, d, s)
    of MulpdX64: x86.emitMulpd(ctx.buf.data, d, s)
    of AddpsX64: x86.emitAddps(ctx.buf.data, d, s)
    of SubpsX64: x86.emitSubps(ctx.buf.data, d, s)
    else: x86.emitMulps(ctx.buf.data, d, s)

  of ShufpsX64:
    # `(shufps D S N)`: xmm registers + an 8-bit immediate lane selector.
    inc n
    let d = parseXmmOperand(n, ctx)
    let s = parseXmmOperand(n, ctx)
    if n.kind != IntLit: error("shufps needs an integer immediate", n)
    let imm = getInt(n)
    if imm < 0 or imm > 255: error("shufps immediate out of range", n)
    inc n
    x86.emitShufps(ctx.buf.data, d, s, byte(imm))

  of AddsdX64, AddssX64, SubsdX64, SubssX64,
     MulsdX64, MulssX64, DivsdX64, DivssX64, Cvtsd2ssX64, Cvtss2sdX64,
     ComisdX64, ComissX64:
    # Scalar SSE op on two XMM registers: `(op (xmmD) (xmmS))` → dest = dest op src
    # (or just sets EFLAGS for comisd/comiss).
    let it = instTag
    inc n
    let d = parseXmmOperand(n, ctx)
    if isXmmOperand(n, ctx):
      let s = parseXmmOperand(n, ctx)
      case it
      of AddsdX64:   x86.emitAddsd(ctx.buf.data, d, s)
      of AddssX64:   x86.emitAddss(ctx.buf.data, d, s)
      of SubsdX64:   x86.emitSubsd(ctx.buf.data, d, s)
      of SubssX64:   x86.emitSubss(ctx.buf.data, d, s)
      of MulsdX64:   x86.emitMulsd(ctx.buf.data, d, s)
      of MulssX64:   x86.emitMulss(ctx.buf.data, d, s)
      of DivsdX64:   x86.emitDivsd(ctx.buf.data, d, s)
      of DivssX64:   x86.emitDivss(ctx.buf.data, d, s)
      of Cvtsd2ssX64: x86.emitCvtsd2ss(ctx.buf.data, d, s)
      of Cvtss2sdX64: x86.emitCvtss2sd(ctx.buf.data, d, s)
      of ComisdX64:  x86.emitComisd(ctx.buf.data, d, s)
      of ComissX64:  x86.emitComiss(ctx.buf.data, d, s)
      else: discard
    else:
      # Folded memory source: `op xmm, m32/m64` — same opcode bytes, RM form.
      let s = parseOperand(n, ctx)
      if s.kind != okMem:
        error("scalar SSE source must be an xmm register or memory", n)
      let (prefix, opcode) = case it
        of AddsdX64:    (0xF2u8, 0x58u8)
        of AddssX64:    (0xF3u8, 0x58u8)
        of SubsdX64:    (0xF2u8, 0x5Cu8)
        of SubssX64:    (0xF3u8, 0x5Cu8)
        of MulsdX64:    (0xF2u8, 0x59u8)
        of MulssX64:    (0xF3u8, 0x59u8)
        of DivsdX64:    (0xF2u8, 0x5Eu8)
        of DivssX64:    (0xF3u8, 0x5Eu8)
        of Cvtsd2ssX64: (0xF2u8, 0x5Au8)
        of Cvtss2sdX64: (0xF3u8, 0x5Au8)
        of ComisdX64:   (0x66u8, 0x2Fu8)
        else:           (0x00u8, 0x2Fu8)   # ComissX64
      x86.emitSseOpMem(ctx.buf.data, prefix, opcode, d, s.mem)

  of Cvtsi2sdX64, Cvtsi2ssX64:
    # int -> float: `(cvtsi2sd (xmmD) gprS)`; the GPR source may be a named local.
    let it = instTag
    inc n
    let d = parseXmmOperand(n, ctx)
    let s = parseOperand(n, ctx).reg
    if it == Cvtsi2sdX64: x86.emitCvtsi2sd(ctx.buf.data, d, s)
    else:                 x86.emitCvtsi2ss(ctx.buf.data, d, s)

  of Cvttsd2siX64, Cvttss2siX64:
    # float -> int (truncating): `(cvttsd2si gprD (xmmS))`; GPR dest may be a local.
    let it = instTag
    inc n
    let d = parseDest(n, ctx).reg
    let s = parseXmmOperand(n, ctx)
    if it == Cvttsd2siX64: x86.emitCvttsd2si(ctx.buf.data, d, s)
    else:                  x86.emitCvttss2si(ctx.buf.data, d, s)

  of MovfqX64, MovfdX64:
    # Bit-transfer between a GPR and an XMM register; direction by operand kinds.
    # `(movfq (xmmD) gprS)` = gpr→xmm; `(movfq gprD (xmmS))` = xmm→gpr. The GPR
    # side may be a raw register or a named local. `(movfq (xmmD) (xmmS))` is the
    # SSE `movq xmm,xmm` (F3 0F 7E): D.lo = S.lo, D's HIGH lane zeroed — the lane
    # sanitizer gcc emits before packed ops on a scalar value (movfq only).
    let it = instTag
    inc n
    if isXmmOperand(n, ctx):
      let d = parseXmmOperand(n, ctx)
      if isXmmOperand(n, ctx):
        if it != MovfqX64: error("movfd between two xmm registers is not encodable", n)
        let s = parseXmmOperand(n, ctx)
        x86.emitMovqXmmToXmm(ctx.buf.data, d, s)
      else:
        let s = parseOperand(n, ctx).reg
        if it == MovfqX64: x86.emitMovqGprToXmm(ctx.buf.data, d, s)
        else:              x86.emitMovdGprToXmm(ctx.buf.data, d, s)
    else:
      let d = parseDest(n, ctx).reg
      let s = parseXmmOperand(n, ctx)
      if it == MovfqX64: x86.emitMovqXmmToGpr(ctx.buf.data, d, s)
      else:              x86.emitMovdXmmToGpr(ctx.buf.data, d, s)

  of LockX64:
    inc n
    if n.kind != TagLit: error("Expected instruction to lock", n)
    let innerInstTag = tagToX64Inst(n.tag)
    if isEscapedTag(n): inc n  # as in `genInstX64`: step over the escaped id
    case innerInstTag
    of AddX64:
      inc n
      let dest = parseDest(n, ctx)
      let op = parseOperand(n, ctx)
      checkIntegerArithmetic(dest.typ, "lock add", start)
      checkIntegerArithmetic(op.typ, "lock add", start)
      checkCompatibleTypes(dest.typ, op.typ, "lock add", start)
      if dest.kind != okMem: error("Atomic ADD requires memory destination", n)
      if op.kind == okMem: error("Atomic ADD memory source not supported", n)
      if op.kind == okImm:
        # `lock <alu> [mem], imm` — the sized imm emitters already exist;
        # ARC refcounting compiles to exactly this shape (`lock add [r], 1`).
        x86.emitLock(ctx.buf.data)
        x86.emitAddImm(ctx.buf.data, dest.mem, int32(op.immVal), intMemAccess(dest.typ).bits)
        return
      x86.emitLock(ctx.buf.data)
      x86.emitAdd(ctx.buf.data, dest.mem, op.reg)
    of SubX64:
      inc n
      let dest = parseDest(n, ctx)
      let op = parseOperand(n, ctx)
      checkIntegerArithmetic(dest.typ, "lock sub", start)
      checkIntegerArithmetic(op.typ, "lock sub", start)
      checkCompatibleTypes(dest.typ, op.typ, "lock sub", start)
      if dest.kind != okMem: error("Atomic SUB requires memory destination", n)
      if op.kind == okMem: error("Atomic SUB memory source not supported", n)
      if op.kind == okImm:
        # `lock <alu> [mem], imm` — the sized imm emitters already exist;
        # ARC refcounting compiles to exactly this shape (`lock add [r], 1`).
        x86.emitLock(ctx.buf.data)
        x86.emitSubImm(ctx.buf.data, dest.mem, int32(op.immVal), intMemAccess(dest.typ).bits)
        return
      x86.emitLock(ctx.buf.data)
      x86.emitSub(ctx.buf.data, dest.mem, op.reg)
    of AndX64:
      inc n
      let dest = parseDest(n, ctx)
      let op = parseOperand(n, ctx)
      checkBitwiseType(dest.typ, "lock and", start)
      checkBitwiseType(op.typ, "lock and", start)
      checkCompatibleTypes(dest.typ, op.typ, "lock and", start)
      if dest.kind != okMem: error("Atomic AND requires memory destination", n)
      if op.kind == okMem: error("Atomic AND memory source not supported", n)
      if op.kind == okImm:
        # `lock <alu> [mem], imm` — the sized imm emitters already exist;
        # ARC refcounting compiles to exactly this shape (`lock add [r], 1`).
        x86.emitLock(ctx.buf.data)
        x86.emitAndImm(ctx.buf.data, dest.mem, int32(op.immVal), intMemAccess(dest.typ).bits)
        return
      x86.emitLock(ctx.buf.data)
      x86.emitAnd(ctx.buf.data, dest.mem, op.reg)
    of OrX64:
      inc n
      let dest = parseDest(n, ctx)
      let op = parseOperand(n, ctx)
      checkBitwiseType(dest.typ, "lock or", start)
      checkBitwiseType(op.typ, "lock or", start)
      checkCompatibleTypes(dest.typ, op.typ, "lock or", start)
      if dest.kind != okMem: error("Atomic OR requires memory destination", n)
      if op.kind == okMem: error("Atomic OR memory source not supported", n)
      if op.kind == okImm:
        # `lock <alu> [mem], imm` — the sized imm emitters already exist;
        # ARC refcounting compiles to exactly this shape (`lock add [r], 1`).
        x86.emitLock(ctx.buf.data)
        x86.emitOrImm(ctx.buf.data, dest.mem, int32(op.immVal), intMemAccess(dest.typ).bits)
        return
      x86.emitLock(ctx.buf.data)
      x86.emitOr(ctx.buf.data, dest.mem, op.reg)
    of XorX64:
      inc n
      let dest = parseDest(n, ctx)
      let op = parseOperand(n, ctx)
      checkBitwiseType(dest.typ, "lock xor", start)
      checkBitwiseType(op.typ, "lock xor", start)
      checkCompatibleTypes(dest.typ, op.typ, "lock xor", start)
      if dest.kind != okMem: error("Atomic XOR requires memory destination", n)
      if op.kind == okMem: error("Atomic XOR memory source not supported", n)
      if op.kind == okImm:
        # `lock <alu> [mem], imm` — the sized imm emitters already exist;
        # ARC refcounting compiles to exactly this shape (`lock add [r], 1`).
        x86.emitLock(ctx.buf.data)
        x86.emitXorImm(ctx.buf.data, dest.mem, int32(op.immVal), intMemAccess(dest.typ).bits)
        return
      x86.emitLock(ctx.buf.data)
      x86.emitXor(ctx.buf.data, dest.mem, op.reg)
    of IncX64:
      inc n
      let dest = parseDest(n, ctx)
      checkIntegerArithmetic(dest.typ, "lock inc", start)
      if dest.kind != okMem: error("Atomic INC requires memory destination", n)
      x86.emitLock(ctx.buf.data)
      x86.emitInc(ctx.buf.data, dest.mem)
    of DecX64:
      inc n
      let dest = parseDest(n, ctx)
      checkIntegerArithmetic(dest.typ, "lock dec", start)
      if dest.kind != okMem: error("Atomic DEC requires memory destination", n)
      x86.emitLock(ctx.buf.data)
      x86.emitDec(ctx.buf.data, dest.mem)
    of NotX64:
      inc n
      let dest = parseDest(n, ctx)
      checkBitwiseType(dest.typ, "lock not", start)
      if dest.kind != okMem: error("Atomic NOT requires memory destination", n)
      x86.emitLock(ctx.buf.data)
      x86.emitNot(ctx.buf.data, dest.mem)
    of NegX64:
      inc n
      let dest = parseDest(n, ctx)
      checkIntegerArithmetic(dest.typ, "lock neg", start)
      if dest.kind != okMem: error("Atomic NEG requires memory destination", n)
      x86.emitLock(ctx.buf.data)
      x86.emitNeg(ctx.buf.data, dest.mem)
    of XaddX64:
      # `lock xadd [mem], reg` — atomic exchange-and-add; reg receives the old value.
      inc n
      let dest = parseDest(n, ctx)
      let op = parseOperand(n, ctx)
      if dest.kind != okMem: error("Atomic XADD requires memory destination", n)
      if op.kind != okReg: error("Atomic XADD source must be a register", n)
      x86.emitLock(ctx.buf.data)
      x86.emitXadd(ctx.buf.data, dest.mem, op.reg, intMemAccess(dest.typ).bits)
    of CmpxchgX64:
      # `lock cmpxchg [mem], reg` — compares RAX with [mem]; on equal stores reg,
      # else loads [mem] into RAX. ZF reflects success.
      inc n
      let dest = parseDest(n, ctx)
      let op = parseOperand(n, ctx)
      if dest.kind != okMem: error("Atomic CMPXCHG requires memory destination", n)
      if op.kind != okReg: error("Atomic CMPXCHG source must be a register", n)
      x86.emitLock(ctx.buf.data)
      x86.emitCmpxchg(ctx.buf.data, dest.mem, op.reg, intMemAccess(dest.typ).bits)
    else:
       error("Unsupported instruction for LOCK prefix: " & $innerInstTag, n)

    # Each inner branch already consumed the inner instruction (including its
    # closing `)`), so `n` is now at the `(lock …)` form's own closing paren.

  of XchgX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    checkExchangeType(dest.typ, "xchg", start)    # int OR pointer (atomic ptr swap)
    checkExchangeType(op.typ, "xchg", start)
    checkCompatibleTypes(dest.typ, op.typ, "xchg", start)
    if dest.kind == okMem:
      if op.kind == okImm: error("XCHG memory, immediate not supported", n)
      if op.kind == okMem: error("XCHG memory, memory not supported", n)
      x86.emitXchg(ctx.buf.data, dest.mem, op.reg, intMemAccess(dest.typ).bits)
    else:
      if op.kind == okImm: error("XCHG reg, immediate not supported", n)
      if op.kind == okMem:
        x86.emitXchg(ctx.buf.data, op.mem, dest.reg)
      else:
        x86.emitXchg(ctx.buf.data, dest.reg, op.reg)
  of XaddX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    checkIntegerType(dest.typ, "xadd", start)
    checkIntegerType(op.typ, "xadd", start)
    checkCompatibleTypes(dest.typ, op.typ, "xadd", start)
    if dest.kind == okMem:
      if op.kind == okImm: error("XADD memory, immediate not supported", n)
      if op.kind == okMem: error("XADD memory, memory not supported", n)
      x86.emitXadd(ctx.buf.data, dest.mem, op.reg, intMemAccess(dest.typ).bits)
    else:
      if op.kind == okImm: error("XADD reg, immediate not supported", n)
      if op.kind == okMem: error("XADD reg, memory not supported (dest must be r/m, src must be r)", n)
      x86.emitXadd(ctx.buf.data, dest.reg, op.reg)
  of CmpxchgX64:
    inc n
    let dest = parseDest(n, ctx)
    let op = parseOperand(n, ctx)
    checkIntegerType(dest.typ, "cmpxchg", start)
    checkIntegerType(op.typ, "cmpxchg", start)
    checkCompatibleTypes(dest.typ, op.typ, "cmpxchg", start)
    if dest.kind == okMem:
      if op.kind == okImm: error("CMPXCHG memory, immediate not supported", n)
      if op.kind == okMem: error("CMPXCHG memory, memory not supported", n)
      x86.emitCmpxchg(ctx.buf.data, dest.mem, op.reg, intMemAccess(dest.typ).bits)
    else:
      if op.kind == okImm: error("CMPXCHG reg, immediate not supported", n)
      if op.kind == okMem: error("CMPXCHG reg, memory not supported (dest must be r/m, src must be r)", n)
      x86.emitCmpxchg(ctx.buf.data, dest.reg, op.reg)
  of Cmpxchg8bX64:
    inc n
    let dest = parseDest(n, ctx)
    if dest.kind == okMem:
      x86.emitCmpxchg8b(ctx.buf.data, dest.mem)
    else:
      x86.emitCmpxchg8b(ctx.buf.data, dest.reg)
  of MfenceX64:
    inc n
    x86.emitMfence(ctx.buf.data)
  of SfenceX64:
    inc n
    x86.emitSfence(ctx.buf.data)
  of LfenceX64:
    inc n
    x86.emitLfence(ctx.buf.data)
  of PauseX64:
    inc n
    x86.emitPause(ctx.buf.data)

  of ClflushX64:
    inc n
    let op = parseDest(n, ctx)
    if op.kind == okMem: error("CLFLUSH expects memory operand via register?", n)
    # emitClflush(Register). x86.nim takes Register. CLFLUSH m8. ModRM encodes address.
    # So it takes a register which holds the address? No, it takes an address.
    # x86.nim implementation: emitClflush(reg) -> 0F AE /7 (CLFLUSH m8).
    # encodeModRM(amDirect, 7, int(reg)).
    # amDirect means register mode (11).
    # CLFLUSH requires memory operand (ModRM != 11).
    # So emitClflush in x86.nim is BUGGY if it uses amDirect!
    # It should use amIndirect or whatever.
    # If emitClflush(reg) means "flush address in reg", it should be [reg].
    # I'll leave it for now but this looks suspicious.
    x86.emitClflush(ctx.buf.data, op.reg)

  of ClflushoptX64:
    inc n
    let op = parseDest(n, ctx)
    x86.emitClflushopt(ctx.buf.data, op.reg)
  of Prefetcht0X64:
    inc n
    let op = parseDest(n, ctx)
    x86.emitPrefetchT0(ctx.buf.data, op.reg)
  of Prefetcht1X64:
    inc n
    let op = parseDest(n, ctx)
    x86.emitPrefetchT1(ctx.buf.data, op.reg)
  of Prefetcht2X64:
    inc n
    let op = parseDest(n, ctx)
    x86.emitPrefetchT2(ctx.buf.data, op.reg)
  of PrefetchntaX64:
    inc n
    let op = parseDest(n, ctx)
    x86.emitPrefetchNta(ctx.buf.data, op.reg)


proc pass2(n: Cursor; ctx: var GenContext) =
  ## Pass2: Generate code only for top-level instructions (entry point).
  ## Declarations (procs, rodata, gvars, etc.) are NOT generated here,
  ## EXCEPT for entry point procs (named `_start`).
  ## Other declarations are only generated when referenced via lookupWithAutoImport,
  ## which marks them as used and adds them to the pending list.
  ## This enables dead code elimination for the main module.
  var n = n
  if n.kind == TagLit and n.tag == StmtsTagId:
    loopInto n:
      if n.kind == TagLit:
        let start = n
        let declTag = tagToNifasmDecl(n.tag)
        case declTag
        of TypeD:
          # Types were fully handled in pass1; skip the definition body.
          n = start
          skip n
        of ProcD:
          # Check if this is an entry point proc (_start or main.0)
          inc n
          if n.kind != SymbolDef:
            error("Expected symbol definition", n)
          let name = symName(n)
          let sym = lookupWithAutoImport(ctx, ctx.scope, name, n)
          if sym != nil and sym.isForeign:
            # Skip foreign proc body
            n = start
            skip n
          elif name == "_start" or name == "main.0":
            # Entry point proc - generate it immediately. Mark it generated so
            # processReachableSymbols (which sees it in the pending list via the
            # lookupWithAutoImport above) does not emit a duplicate copy.
            n = start
            pass2Proc(n, ctx)
            ctx.generatedSymbols.incl name
            ctx.entrySym = sym             # the FS-setup prologue jumps here
          else:
            # Regular proc - skip, will be generated if referenced
            n = start
            skip n
        of RodataD, GvarD, TvarD:
          # Declarations are NOT generated here - they are subject to dead code elimination.
          # They will only be generated when referenced via lookupWithAutoImport.
          # Skip the declaration body.
          n = start
          skip n
        of ArchD:
          handleArch(n, ctx)
        of ImpD, ExtprocD, SyprocD:
          # Already handled in pass1, skip. A syproc emits no code: it is a
          # syscall's proctype + number, consulted by the `(syscall)`/`(svc)` marker.
          skip n
        else:
          # Top-level instructions (entry point) - generate these
          genInst(n, ctx)
      else:
        error("Expected instruction", n)
  else:
    error("Expected stmts", n)

proc dwarfArchOf(arch: Arch): DwarfArch {.inline.} =
  if arch in {Arch.A64, Arch.WinA64, Arch.LinuxA64}: dwA64 else: dwX64

proc appendTraceTable(ctx: var GenContext) =
  ## Reserve the stack-trace table at the end of `.text` and define the label that
  ## addresses it. Only the SPACE is reserved here: the proc positions it records
  ## are still going to move under the jump shortener and the alignment pass, so
  ## the bytes are written by `fillTraceTable` once those are done. The size does
  ## not move — layout changes where a proc is, never how many there are or what
  ## they are called.
  ##
  ## Called for every target, from `assemble`, and only when something referenced
  ## the symbol: a program that never asks for a stack trace carries no table.
  if not ctx.traceUsed: return
  # Start the blob on an 8-byte boundary. A courtesy, not a guarantee: the layout
  # passes shift it by whatever they add or remove ahead of it, so the reader must
  # tolerate an unaligned table anyway — which it does, since every field is a
  # `u32` and both targets permit unaligned word loads.
  while (ctx.buf.data.len and 7) != 0: ctx.buf.data.add 0'u8
  ctx.buf.defineLabel(ctx.traceLabel)
  let n = traceTableSize(collectTraceProcs(ctx.unwind, dwarfArchOf(ctx.arch)))
  for i in 0 ..< n: ctx.buf.data.add 0'u8

proc fillTraceTable(a: var GenContext) =
  ## Write the reserved table, now that every proc's final code position is known.
  ## Runs after each writer's layout passes and before it copies `a.buf.data` out.
  if not a.traceUsed: return
  var at = -1
  for ld in a.buf.labels:
    if ld.id == a.traceLabel: at = ld.position
  if at < 0: return
  let bytes = encodeTraceTable(collectTraceProcs(a.unwind, dwarfArchOf(a.arch)), at)
  # The reservation is computed from the same `collectTraceProcs`, so a mismatch
  # means a layout pass grew or dropped a proc between the two calls — silently
  # writing a truncated table would produce a stack trace with invented names.
  if at + bytes.len > a.buf.data.len:
    quit "nifasm: trace table outgrew its reservation (" & $bytes.len & " bytes at " & $at & ")"
  for i in 0 ..< bytes.len: a.buf.data[at + i] = bytes[i]

proc writeElf(a: var GenContext; outfile: string) =
  # Shorten x86 rel32 jumps to rel8 where they fit (static-ELF x64 only: no IAT
  # call-site bookkeeping to invalidate, and AArch64 forms are fixed-size). This
  # relays out `.text`, so remap every code byte-offset we still need afterwards:
  # the gvar `lea`/`adrp` patch sites and the synthesized entry stub.
  # Arch-agnostic jump threading + dead-jump prune runs FIRST (both arches): it removes
  # unconditional jumps to their own fall-through and threads branch chains, which also
  # exposes more rel8 opportunities for the x64 shortener below. Both passes return an
  # old→new position map; apply them in sequence to every external code offset we track
  # (gvar `lea`/`adrp` patch sites, the entry stub).
  block:
    let threadMap = threadJumps(a.buf)
    for k in 0 ..< a.gvarSites.len:
      a.gvarSites[k] = (threadMap[a.gvarSites[k][0]], a.gvarSites[k][1])
    if a.entryStubOffset >= 0:
      a.entryStubOffset = threadMap[a.entryStubOffset]
    a.remapListing(threadMap)
    a.remapUnwind(threadMap)
  block:
    # `jcc L; jmp M; L:` ⇒ `jncc M` — folds a conditional branch and its fall-through
    # unconditional jump into one branch. Pattern detection is arch-agnostic (runs on
    # both arches); only the opcode flip inside is arch-specific.
    let invMap = invertCondJumps(a.buf)
    for k in 0 ..< a.gvarSites.len:
      a.gvarSites[k] = (invMap[a.gvarSites[k][0]], a.gvarSites[k][1])
    if a.entryStubOffset >= 0:
      a.entryStubOffset = invMap[a.entryStubOffset]
    a.remapListing(invMap)
    a.remapUnwind(invMap)
  if a.arch == Arch.X64:
    # Code-alignment candidates, as LABEL IDS (stable across the layout passes):
    # every generated proc's entry + every loop head (= target of a backward
    # jmp/jcc, collected now — after shortening those jumps are patched inline
    # and no longer tracked). The shortener keeps any jump whose displacement a
    # pad would change in rel32 form; `alignCodeX64` then inserts the NOP pads
    # so entries and loop heads start on a 16-byte boundary (gcc pads ~2.7k NOPs
    # into the same workload; nifasm previously aligned nothing, which both
    # costs fetch bandwidth on hot loop heads and made wall-clock timings swing
    # with incidental layout shifts).
    var alignLabels: seq[int] = @[]
    for name, sym in a.rootScope.syms:
      if sym.kind == skProc: alignLabels.add sym.offset
    for id in backwardBranchTargets(a.buf): alignLabels.add id
    let posMap = shortenX64Jumps(a.buf, alignLabels)
    for k in 0 ..< a.gvarSites.len:
      a.gvarSites[k] = (posMap[a.gvarSites[k][0]], a.gvarSites[k][1])
    if a.entryStubOffset >= 0:
      a.entryStubOffset = posMap[a.entryStubOffset]
    a.remapListing(posMap)
    a.remapUnwind(posMap)
    let alignMap = alignCodeX64(a.buf, alignLabels)
    for k in 0 ..< a.gvarSites.len:
      a.gvarSites[k] = (alignMap[a.gvarSites[k][0]], a.gvarSites[k][1])
    if a.entryStubOffset >= 0:
      a.entryStubOffset = alignMap[a.entryStubOffset]
    a.remapListing(alignMap)
    a.remapUnwind(alignMap)
  when defined(arkhamDbgReloc):
    block validateRelocs:
      var defined = initHashSet[int]()
      var labelPos = initTable[int, int]()
      for ld in a.buf.labels: (defined.incl int(ld.id); labelPos[int(ld.id)] = ld.position)
      var idToName = initTable[int, string]()
      var procRows: seq[(int, string)]
      for name, sym in a.rootScope.syms:
        if sym.offset >= 0: idToName[sym.offset] = name
        if sym.kind == skProc and labelPos.hasKey(sym.offset):
          procRows.add (labelPos[sym.offset], name)
      procRows.sort(proc (x, y: (int, string)): int = cmp(x[0], y[0]))
      var bad = 0
      for r in a.buf.relocs:
        if not defined.contains(int(r.target)):
          inc bad
          var enc = "?"
          for (p, nm) in procRows:
            if p <= r.position: enc = nm else: break
          if bad <= 30:
            stderr.writeLine "MISSING LABEL: reloc pos=" & $r.position & " kind=" & $r.kind &
              " targetId=" & $int(r.target) & " targetName=" &
              idToName.getOrDefault(int(r.target), "<no-name>") & " in proc " & enc
      if bad > 0: stderr.writeLine "TOTAL MISSING LABELS: " & $bad
  finalize(a.buf)
  finalize(a.bssBuf)
  # `--symmap`: dump every generated proc's virtual address to stderr (the ELF
  # carries no symbol table), so a disassembler can locate a function by name.
  if a.symMap:
    var labelPos = initTable[int, int]()
    for ld in a.buf.labels: labelPos[int(ld.id)] = ld.position
    let hdrBytes = 64 + 56 * 3
    var rows: seq[(int, string)]
    for name, sym in a.rootScope.syms:
      if sym.kind == skProc and labelPos.hasKey(sym.offset):
        rows.add (0x400000 + hdrBytes + labelPos[sym.offset], a.nameOf(name))
    rows.sort(proc (x, y: (int, string)): int = cmp(x[0], y[0]))
    for (va, name) in rows: stderr.writeLine "0x" & toHex(va, 6) & "  " & name
  if a.listing:
    # `.text` byte 0 lands right after the ELF header + the three program headers,
    # the same arithmetic `--symmap` above does.
    a.writeListing(a.listingPath, 0x400000 + 64 + 56 * 3)
  fillTraceTable(a)
  var code = a.buf.data
  let baseAddr = 0x400000.uint64
  let headersSize = 64 + (56 * 3)  # ELF header + 3 program headers
  let pageSize = 0x1000.uint64

  # Calculate addresses and sizes
  # The LOAD segment must start at file offset 0 to include headers
  # (some kernels like WSL require this for proper loading)
  let textOffset = 0.uint64  # Include headers in LOAD segment
  let textVaddr = baseAddr   # Segment starts at base address
  let textFileSize = headersSize.uint64 + code.len.uint64  # Headers + code
  let textMemSize = (textFileSize + pageSize - 1) and not (pageSize - 1)

  # Entry point is after the headers. When nifasm synthesized an entry stub — the
  # x86-64 FS-setup prologue (`setupTls`) or the AArch64 argc/argv/envp prologue
  # (`setupLinuxA64Entry`) — that stub is the real entry and tail-jumps to the
  # program's entry proc; otherwise the entry is the first byte of code (offset 0).
  let entryOff = if a.entryStubOffset >= 0: a.entryStubOffset.uint64 else: 0'u64
  let entryAddr = baseAddr + headersSize.uint64 + entryOff

  # .bss section comes after .text in memory
  let bssVaddr = textVaddr + textMemSize
  let bssSize = a.bssOffset.uint64

  # Patch each global's address into the placeholder instruction(s) now that both
  # segments' virtual addresses are known. The gvar's .bss byte offset is `sym.size`.
  for (pos, sym) in a.gvarSites:
    let instrVaddr = textVaddr + headersSize.uint64 + pos.uint64
    let targetVaddr = bssVaddr + sym.size.uint64
    if a.arch == Arch.LinuxA64:
      # AArch64: a PC-relative `adrp rd, page` + `add rd, rd, #pageoff` pair (the
      # placeholder carries the dest reg with zero immediates, so OR them in). Same
      # encoding as the Mach-O backend's gvar patch.
      let pageDiff = int64(targetVaddr and not 0xFFF'u64) -
                     int64(instrVaddr and not 0xFFF'u64)
      let pageOff = targetVaddr and 0xFFF'u64
      let adrpImm = pageDiff shr 12
      let immlo = uint32(adrpImm and 0x03) shl 29
      let immhi = uint32((adrpImm shr 2) and 0x7FFFF) shl 5
      var adrp = uint32(code[pos]) or (uint32(code[pos+1]) shl 8) or
                 (uint32(code[pos+2]) shl 16) or (uint32(code[pos+3]) shl 24)
      adrp = adrp or immlo or immhi
      code[pos+0] = byte(adrp and 0xFF);          code[pos+1] = byte((adrp shr 8) and 0xFF)
      code[pos+2] = byte((adrp shr 16) and 0xFF); code[pos+3] = byte((adrp shr 24) and 0xFF)
      # pos+4 is `add rd, rd, #pageoff` (address-taking) OR a folded `ldr/str rt,
      # [x17, #pageoff]` (gload/gstore). Load/store unsigned-imm has bits[29:24]==0x39
      # and scales its imm12 by the access size (bits[31:30]); `add` uses the raw offset.
      var lo = uint32(code[pos+4]) or (uint32(code[pos+5]) shl 8) or
               (uint32(code[pos+6]) shl 16) or (uint32(code[pos+7]) shl 24)
      if ((lo shr 24) and 0x3F'u32) == 0x39'u32:
        let size = (lo shr 30) and 0x3'u32
        doAssert (pageOff and ((1'u64 shl size) - 1)) == 0,
          "gload/gstore: global page-offset not aligned to its access size"
        lo = lo or (uint32((pageOff shr size) and 0xFFF) shl 10)
      else:
        lo = lo or (uint32(pageOff and 0xFFF) shl 10)
      code[pos+4] = byte(lo and 0xFF);            code[pos+5] = byte((lo shr 8) and 0xFF)
      code[pos+6] = byte((lo shr 16) and 0xFF);   code[pos+7] = byte((lo shr 24) and 0xFF)
    else:
      # x86-64: a RIP-relative `lea` — 7 bytes with a disp32 at offset +3; RIP points
      # at the next instruction (+7).
      let disp = int32(int64(targetVaddr) - int64(instrVaddr + 7))
      code[pos + 3] = byte(disp and 0xFF)
      code[pos + 4] = byte((disp shr 8) and 0xFF)
      code[pos + 5] = byte((disp shr 16) and 0xFF)
      code[pos + 6] = byte((disp shr 24) and 0xFF)
  # Bake rodata symbol-address relocations (e.g. a vtable/RTTI const whose fields
  # are addresses of other consts or procs). The blob lives in `.text` at its
  # rodata label; write the resolved target vaddr into `code` at `label + blobOff`.
  # Same target-vaddr arithmetic as `bssSymInits`: a proc/rodata label sits at
  # `baseAddr + headers + labelPos`, a gvar at `bssVaddr + its .bss off`.
  if a.rodataSymInits.len > 0:
    var labelPos = initTable[int, int]()
    for ld in a.buf.labels: labelPos[int(ld.id)] = ld.position
    for it in a.rodataSymInits:
      if not labelPos.hasKey(it.labelId): continue
      let sitePos = labelPos[it.labelId] + it.blobOff
      var targetVaddr = 0'u64
      case it.sym.kind
      of skProc, skRodata:
        if labelPos.hasKey(it.sym.offset):
          targetVaddr = baseAddr + headersSize.uint64 + labelPos[it.sym.offset].uint64
      of skGvar:
        targetVaddr = bssVaddr + it.sym.size.uint64
      else: discard
      for i in 0 ..< it.size:
        if sitePos + i < code.len:
          code[sitePos + i] = byte((targetVaddr shr (8 * i)) and 0xFF)
  let bssAlignedSize = if bssSize > 0: ((bssSize + pageSize - 1) and not (pageSize - 1)) else: 0.uint64

  let machine = case a.arch
    of Arch.X64, Arch.LinuxA64:
      if a.arch == Arch.X64: EM_X86_64 else: EM_AARCH64
    else:
      EM_X86_64  # fallback

  # ── debug info: `.symtab` (proc names) and `.eh_frame` (unwind) ─────────────
  # Both are METADATA: nothing the program executes reads either, and they exist so a
  # debugger can name a frame and walk past it — arkham keeps no frame pointer, so
  # without CFI even GDB's prologue heuristic loses the chain after a frame or two
  # (measured: `#2 0x0000000000000000 in ?? ()`).
  #
  # `.symtab`/`.strtab` sit past the last PT_LOAD and cost the running image nothing.
  # `.eh_frame` is the exception: it is `SHF_ALLOC` in a read-only PT_LOAD of its own,
  # because valgrind will not accept CFI it cannot map (see the segment comment below).
  # The cost is a few demand-paged read-only KB no execution path touches.
  #
  # Everything they need is already known here: the proc's final code range (the
  # layout passes above have remapped it), its NIF name, and the CFA states its
  # prologue passes through. See dwarf.nim for why that is only a handful of
  # bytes per proc — SP is constant inside an arkham frame.
  let procVaddrBase = baseAddr + headersSize.uint64
  var ehFrame: seq[byte] = @[]
  var symtab: seq[byte] = @[]
  var strtab: seq[byte] = @[]
  if a.debugInfo:
    # The image's entry, and — when a synthesized stub holds it — the entry PROC
    # the stub tail-jumps to; both are "nothing called me" frames for the FDEs.
    var entryOffs = @[int(entryOff)]
    if a.entrySym != nil:
      for ld in a.buf.labels:
        if int(ld.id) == a.entrySym.offset: entryOffs.add ld.position
    ehFrame = buildEhFrame(a.unwind,
                           (if a.arch == Arch.LinuxA64: dwA64 else: dwX64),
                           procVaddrBase, entryOffs)
    strtab.add 0'u8                                   # index 0 is the empty name
    symtab.setLen sizeof(Elf64_Sym)                   # index 0 is the null symbol
    for p in a.unwind:
      if p.stop <= p.start: continue
      var sym = Elf64_Sym(st_name: Elf64_Word(strtab.len),
                          st_info: (STB_GLOBAL shl 4) or STT_FUNC,
                          st_other: 0, st_shndx: 1,   # section 1 is `.text`
                          st_value: procVaddrBase + uint64(p.start),
                          st_size: uint64(p.stop - p.start))
      for ch in p.name: strtab.add byte(ch)
      strtab.add 0'u8
      let at = symtab.len
      symtab.setLen at + sizeof(Elf64_Sym)
      copyMem(addr symtab[at], addr sym, sizeof(Elf64_Sym))

  var ehdr = initHeader(entryAddr, machine)
  ehdr.e_phnum = 3  # Three program headers: .text, .bss and .eh_frame
  ehdr.e_phoff = 64  # Program headers start after ELF header

  # Build the initialized .bss image (constant static initializers — e.g. `stdout = 1`,
  # or a gvar's compile-time value) FIRST, so the data LOAD segment below can size its
  # file/mem extents to cover it. The on-disk image holds those bytes (the rest zero),
  # so the slots start initialized with no entry-time code (correct in a bundle).
  var bssImage: seq[byte]
  if (a.bssInits.len > 0 or a.bssSymInits.len > 0) and bssSize > 0:
    bssImage = newSeq[byte](bssSize.int)
    for it in a.bssInits:
      for i in 0 ..< it.size:
        if it.off.int + i < bssImage.len:
          bssImage[it.off.int + i] = byte((it.val shr (8 * i)) and 0xFF)
    # Bake symbol-address initializers (function-pointer hooks etc.). The target's
    # absolute vaddr is known now that `.text` is finalized: a proc/rodata label
    # sits at `baseAddr + headers + labelPos`; a gvar at `bssVaddr + its .bss off`.
    if a.bssSymInits.len > 0:
      var labelPos = initTable[int, int]()
      for ld in a.buf.labels: labelPos[int(ld.id)] = ld.position
      for it in a.bssSymInits:
        var targetVaddr = 0'u64
        case it.sym.kind
        of skProc, skRodata:
          if labelPos.hasKey(it.sym.offset):
            targetVaddr = baseAddr + headersSize.uint64 + labelPos[it.sym.offset].uint64
        of skGvar:
          targetVaddr = bssVaddr + it.sym.size.uint64
        else: discard
        for i in 0 ..< it.size:
          if it.off.int + i < bssImage.len:
            bssImage[it.off.int + i] = byte((targetVaddr shr (8 * i)) and 0xFF)
  let bssFileSz = if bssImage.len > 0: bssSize else: 0'u64

  # THREE PT_LOADs, one per permission class:
  #
  #   R-X   headers + code       [0, textMemSize)
  #   RW-   data/bss             [textMemSize, +bssFileSz), zero-filled to bssAlignedSize
  #   R--   .eh_frame            page-aligned, so a debugger can MAP the unwind tables
  #
  # An earlier revision merged all three into ONE R+W+X segment, blaming the AArch64
  # kernel for applying the data segment's permissions to the whole range. That is no
  # longer reproducible (re-tested on Linux 6.12/AArch64: the split layout below loads
  # and runs correctly), and the merged shape cost two things worth having back.
  #
  # It gave up W^X: every code page was writable. And it made the image opaque to
  # valgrind, whose ELF reader classifies a mapping as the "text" map only when it is
  # R+X and *not* writable — so it skipped the object entirely and every frame of every
  # report came out as `???`, which is most of the value of running valgrind at all.
  #
  # `.eh_frame` gets its own read-only segment for the second half of that story:
  # valgrind refuses an `.eh_frame` whose section mapping it cannot place inside a
  # loaded segment ("Can't make sense of .eh_frame section mapping") and treats that as
  # a FATAL debug-info error, which takes `.symtab` down with it. So unlike `.symtab`
  # and `.strtab` — which stay in the unloaded tail, read from the file by section
  # header — the CFI has to be genuinely mapped. It costs a few demand-paged read-only
  # KB that nothing reads unless a debugger walks the stack.
  #
  # Each segment's p_offset is congruent to its p_vaddr modulo the page size, which is
  # what the kernel's mmap of the file requires: the first two are page multiples by
  # construction, and the third is page-aligned on both sides below.
  let ehSize = ehFrame.len.uint64
  let ehSegOff = (textMemSize + bssFileSz + pageSize - 1) and not (pageSize - 1)
  let ehVaddr = bssVaddr + bssAlignedSize

  var textPhdr = initPhdr(textOffset, textVaddr, textMemSize, textMemSize,
                          PF_R or PF_X)
  # `memsz > filesz` is the bss zero-fill tail; the segment is writable, so the kernel
  # accepts it.
  var bssPhdr = initPhdr(textMemSize, bssVaddr, bssFileSz, bssAlignedSize,
                         PF_R or PF_W)
  # Kept empty (filesz = memsz = 0) when there is no debug info: a PT_LOAD the kernel
  # ignores, so `e_phnum` — and with it `headersSize` — stays constant either way.
  var ehPhdr =
    if ehSize > 0: initPhdr(ehSegOff, ehVaddr, ehSize, ehSize, PF_R)
    else: initPhdr(0'u64, ehVaddr, 0'u64, 0'u64, PF_R)

  var f = newFileStream(outfile, fmWrite)
  defer: f.close()

  # Write ELF header
  f.write(ehdr)

  # Write program headers
  f.write(textPhdr)
  f.write(bssPhdr)
  f.write(ehPhdr)

  # Write .text section (code)
  if code.len > 0:
    f.writeData(code.rawData, code.len)
    # Pad to page boundary
    let padding = int(textMemSize - textFileSize)
    if padding > 0:
      var zeros = newSeq[byte](padding)
      f.writeData(unsafeAddr zeros[0], padding)

  # Write the initialized .bss image (constant static initializers), if any. The
  # remaining memsz beyond bssSize is zero-filled by the loader.
  if bssImage.len > 0:
    f.writeData(unsafeAddr bssImage[0], bssImage.len)

  if a.debugInfo:
    # `.text` and `.eh_frame` are `SHF_ALLOC` — they describe bytes that are LOADED
    # (the symbols point into the first, a debugger maps the second). `.symtab`,
    # `.strtab` and `.shstrtab` follow in the non-loaded tail, read straight from the
    # file by section header, then the section header table itself.
    var pos = uint64(f.getPosition())
    template pad8() =
      while (pos and 7) != 0:
        f.write 0'u8; inc pos
    # `.eh_frame` starts its own PT_LOAD, so it is padded to a PAGE, not to 8: the
    # kernel maps a segment from a page-aligned file offset, and `ehSegOff` above
    # computed that same boundary.
    while (pos and (pageSize - 1)) != 0:
      f.write 0'u8; inc pos
    let ehFrameOff = pos
    doAssert ehFrameOff == ehSegOff, "`.eh_frame` file offset disagrees with its PT_LOAD"
    if ehFrame.len > 0:
      f.writeData(unsafeAddr ehFrame[0], ehFrame.len); pos += ehFrame.len.uint64
    pad8()
    let symtabOff = pos
    if symtab.len > 0:
      f.writeData(unsafeAddr symtab[0], symtab.len); pos += symtab.len.uint64
    let strtabOff = pos
    if strtab.len > 0:
      f.writeData(unsafeAddr strtab[0], strtab.len); pos += strtab.len.uint64
    # `.shstrtab` — the section NAME strings, in the order the headers below use.
    var shstr: seq[byte] = @[]
    var shName: seq[uint32] = @[]
    shstr.add 0'u8
    for nm in [".text", ".eh_frame", ".symtab", ".strtab", ".shstrtab"]:
      shName.add uint32(shstr.len)
      for ch in nm: shstr.add byte(ch)
      shstr.add 0'u8
    let shstrOff = pos
    f.writeData(unsafeAddr shstr[0], shstr.len); pos += shstr.len.uint64
    pad8()
    let shoff = pos
    var shdrs: seq[Elf64_Shdr] = @[]
    shdrs.add initShdr(0, SHT_NULL, 0, 0, 0, 0, 0, 0, 0, 0)
    shdrs.add initShdr(shName[0], SHT_PROGBITS, SHF_ALLOC or SHF_EXECINSTR,
                       baseAddr + headersSize.uint64, headersSize.uint64,
                       code.len.uint64, 0, 0, 16, 0)
    shdrs.add initShdr(shName[1], SHT_PROGBITS, SHF_ALLOC, ehVaddr, ehFrameOff,
                       ehFrame.len.uint64, 0, 0, 8, 0)
    # `sh_link` of a symtab is its string table; `sh_info` is the index of the
    # first non-local symbol — every symbol here is global, so that is 1.
    shdrs.add initShdr(shName[2], SHT_SYMTAB, 0, 0, symtabOff,
                       symtab.len.uint64, 4, 1, 8, uint64(sizeof(Elf64_Sym)))
    shdrs.add initShdr(shName[3], SHT_STRTAB, 0, 0, strtabOff,
                       strtab.len.uint64, 0, 0, 1, 0)
    shdrs.add initShdr(shName[4], SHT_STRTAB, 0, 0, shstrOff,
                       shstr.len.uint64, 0, 0, 1, 0)
    for sh in shdrs: f.write(sh)
    # Re-write the ELF header now that the section table's offset is known.
    ehdr.e_shoff = shoff
    ehdr.e_shnum = Elf64_Half(shdrs.len)
    ehdr.e_shstrndx = Elf64_Half(shdrs.len - 1)
    f.setPosition(0)
    f.write(ehdr)

  let perms = {fpUserExec, fpGroupExec, fpOthersExec, fpUserRead, fpUserWrite}
  setFilePermissions(outfile, perms)

proc writeMachO(a: var GenContext; outfile: string) =
  fillTraceTable(a)
  finalize(a.buf)
  finalize(a.bssBuf)
  let code = a.buf.data

  # Determine CPU type based on architecture
  let (cputype, cpusubtype) = case a.arch
    of Arch.X64:
      (CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL)
    of Arch.A64, Arch.LinuxA64:
      (CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL)
    of Arch.WinX64, Arch.WinA64, Arch.CortexM:
      # Unreachable: Windows emits PE and Cortex-M emits a bare ELF32 firmware
      # image, so neither ever reaches the Mach-O writer. Covered so the case
      # stays exhaustive.
      (CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL)

  # Build dynlink info for external procs
  var dynlink: macho.DynLinkInfo
  for lib in a.imports:
    dynlink.libs.add macho.ImportedLibInfo(name: lib.name, ordinal: lib.ordinal)
  for ext in a.extProcs:
    dynlink.extProcs.add macho.ExternalProcInfo(
      name: ext.name, extName: ext.extName,
      libOrdinal: ext.libOrdinal, gotSlot: ext.gotSlot,
      callSites: ext.callSites)

  var gsites: seq[(int, int)] = @[]   # resolve each global's final .bss offset now
  for (pos, sym) in a.gvarSites: gsites.add (pos, sym.size)

  # Thread-local storage (macOS TLV): one 24-byte descriptor per tvar, the
  # __thread_data init template, and the adrp+add sites referencing each
  # descriptor (carried by descriptor index).
  var tlv: macho.TlvInfo
  for sym in a.tlvSyms: tlv.descriptorOffsets.add sym.size
  tlv.threadData = a.tlvData
  for (pos, sym) in a.tlvSites: tlv.sites.add (pos, sym.offset)

  # Symbol-pointer fields of `dataConst` blobs (now in __DATA): resolve each to its
  # target's preferred vaddr and a dyld rebase. A target in __TEXT (a plain rodata
  # const or a proc) is located by its finalized label position; a target itself in
  # __DATA (another data const, or a gvar) by its `.bss`/__DATA offset.
  var labelPos = initTable[int, int]()
  for ld in a.buf.labels: labelPos[int(ld.id)] = ld.position
  var rebases: seq[macho.RodataRebase] = @[]
  for it in a.rodataRebases:
    let fieldOff = it.owner.size + it.blobOff
    case it.target.kind
    of skProc, skRodata:
      if it.target.kind == skRodata and it.target.dataConst:
        rebases.add macho.RodataRebase(fieldOff: fieldOff, targetInData: true,
                                       targetOff: it.target.size)
      elif labelPos.hasKey(it.target.offset):
        rebases.add macho.RodataRebase(fieldOff: fieldOff, targetInData: false,
                                       targetOff: labelPos[it.target.offset])
    of skGvar:
      rebases.add macho.RodataRebase(fieldOff: fieldOff, targetInData: true,
                                     targetOff: it.target.size)
    else: discard

  # A GVAR whose initializer is a symbol ADDRESS (`(gvar :scheduler (proctype …)
  # trivialTick.0)` — a function-pointer hook, or a global pointing at another
  # global). Same treatment as the blob fields above: bake the target's preferred
  # vaddr and let dyld slide it. `writeElf` bakes these into its .bss image; this
  # path used to drop them, so on macOS every such global started as NULL and the
  # first call through it branched to 0.
  for it in a.bssSymInits:
    case it.sym.kind
    of skProc, skRodata:
      if it.sym.kind == skRodata and it.sym.dataConst:
        rebases.add macho.RodataRebase(fieldOff: it.off.int, targetInData: true,
                                       targetOff: it.sym.size)
      elif labelPos.hasKey(it.sym.offset):
        rebases.add macho.RodataRebase(fieldOff: it.off.int, targetInData: false,
                                       targetOff: labelPos[it.sym.offset])
    of skGvar:
      rebases.add macho.RodataRebase(fieldOff: it.off.int, targetInData: true,
                                     targetOff: it.sym.size)
    else: discard

  # `--symmap`: dump every generated proc's virtual address (the Mach-O carries no
  # symbol table). Only `writeMachO` knows where __text lands, so hand it the rows.
  var symMapRows: seq[(int, string)] = @[]
  if a.symMap:
    for name, sym in a.rootScope.syms:
      if sym.kind == skProc and labelPos.hasKey(sym.offset):
        symMapRows.add (labelPos[sym.offset], a.nameOf(name))
    symMapRows.sort(proc (x, y: (int, string)): int = cmp(x[0], y[0]))
  if a.listing:
    # Only `writeMachO` knows where __text lands, so these rows stay __text-relative;
    # the header line says so.
    a.writeListing(a.listingPath, 0)

  # `LC_SYMTAB` + `__TEXT,__eh_frame` from the same per-proc facts the ELF path
  # encodes: proc names for lldb, and CFI so it can unwind a frame-pointer-less
  # stack. Both are debugger-only; `--no-debug-info` drops them.
  macho.writeMachO(code, a.bssOffset, cputype, cpusubtype, outfile, dynlink, gsites, tlv,
                   a.bssInits, rebases, symMapRows,
                   (if a.debugInfo: a.unwind else: @[]))

  # macOS arm64 requires code signing for all executables
  when defined(macosx):
    let codesignResult = execCmd("codesign -s - " & quoteShell(outfile))
    if codesignResult != 0:
      raise newException(OSError, "codesign failed with exit code " & $codesignResult)

proc machoName(name: string): string =
  ## Mangle a nifasm symbol into a Mach-O symbol. macOS C ABI prefixes globals
  ## with `_`; nifasm's internal names (e.g. `foo.0.mod`) only need a stable,
  ## collision-free spelling, and `.` is valid in Mach-O symbol names.
  "_" & name

proc writeMachOObject(a: var GenContext; outfile: string) =
  ## Emit a relocatable object instead of a standalone executable. Defined procs /
  ## globals become exported symbols, external `extproc` references become undefined
  ## symbols, and every fixup the executable path would resolve in-place (external
  ## calls, gvar `adrp`/`add`, symbol-address initializers) becomes a relocation the
  ## system linker resolves. The standalone `writeMachO` above is left untouched.
  fillTraceTable(a)
  finalize(a.buf)
  finalize(a.bssBuf)
  let code = a.buf.data

  let (cputype, cpusubtype) = case a.arch
    of Arch.A64: (CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL)
    else:
      quit "nifasm: --emit-obj is only supported for macOS arm64"

  if a.tlvSyms.len > 0:
    quit "nifasm: --emit-obj does not yet support thread-local variables"

  var labelPos = initTable[int, int]()
  for ld in a.buf.labels: labelPos[int(ld.id)] = ld.position
  let dataRegionSize = a.bssOffset   # local copy: the nested procs below must not
                                     # capture the `var GenContext` param

  # --- symbol table: defined first, then undefined (Mach-O dysymtab ordering) ----
  var syms: seq[macho.MachOSym] = @[]
  var defIndex = initTable[string, int]()   # mangled name -> index in `syms`

  proc addDef(name: string; sec: macho.MachOSecKind; value: uint64): int =
    result = defIndex.getOrDefault(name, -1)
    if result < 0:
      result = syms.len
      defIndex[name] = result
      syms.add macho.MachOSym(name: name, sec: sec, value: value, defined: true)

  let mpool = a.pool   # capturable pool ref (the nested `defOf` cannot close over `a`)
  proc defOf(sym: Symbol): int =
    ## Ensure `sym` is in the table as a defined symbol; return its index (or -1 if
    ## it has no resolvable location, e.g. an un-emitted proc).
    case sym.kind
    of skProc:
      if labelPos.hasKey(sym.offset):
        addDef(machoName(poolSym(mpool, sym.name)), macho.moText, uint64(labelPos[sym.offset]))
      else: -1
    of skRodata:
      if sym.dataConst:
        (if sym.size < dataRegionSize: addDef(machoName(poolSym(mpool, sym.name)), macho.moData, uint64(sym.size)) else: -1)
      elif labelPos.hasKey(sym.offset):
        addDef(machoName(poolSym(mpool, sym.name)), macho.moText, uint64(labelPos[sym.offset]))
      else: -1
    of skGvar:
      # A data symbol must point inside the emitted `__data` region; a zero-size
      # region (`bssOffset == 0`) emits no `__data` section, so skip it then.
      if sym.size < dataRegionSize: addDef(machoName(poolSym(mpool, sym.name)), macho.moData, uint64(sym.size))
      else: -1
    else: -1

  # All generated procs (and data referenced below) become exported symbols. The
  # synthetic per-thread TLS block is an internal artifact (unused on arm64), never
  # a real exported global.
  for name in a.generatedSymbols:
    if name == "arkham.tls.0": continue
    let sym = a.rootScope.lookup(a.symIdOf(name))
    if sym != nil: discard defOf(sym)

  # An `_main` alias at the entry proc so the system crt can find it.
  if a.entrySym != nil and labelPos.hasKey(a.entrySym.offset):
    discard addDef("_main", macho.moText, uint64(labelPos[a.entrySym.offset]))

  # --- relocations ---------------------------------------------------------------
  # The reloc loops below also pull their *defined* targets into the table via
  # `defOf`. Mach-O requires every defined symbol to precede every undefined one,
  # so we gather all of these (and their relocs) BEFORE allocating any undef index.
  var textRels: seq[macho.MachORel] = @[]
  var dataRels: seq[macho.MachORel] = @[]

  # gvar references: the `adrp`/`add` pair → PAGE21 + PAGEOFF12 to the data symbol.
  for (pos, sym) in a.gvarSites:
    let si = defOf(sym)
    if si >= 0:
      textRels.add macho.MachORel(address: pos, symIdx: si, kind: macho.mrPage21)
      textRels.add macho.MachORel(address: pos + 4, symIdx: si, kind: macho.mrPageoff12)

  # Symbol-address pointer fields inside a rodata blob (in __text): 8-byte UNSIGNED.
  for (labelId, blobOff, sym, _) in a.rodataSymInits:
    let si = defOf(sym)
    if si >= 0 and labelPos.hasKey(labelId):
      textRels.add macho.MachORel(address: labelPos[labelId] + blobOff,
                                  symIdx: si, kind: macho.mrUnsigned)

  # Symbol-address initializers of globals (in __data): 8-byte UNSIGNED.
  for (off, sym, _) in a.bssSymInits:
    let si = defOf(sym)
    if si >= 0:
      dataRels.add macho.MachORel(address: int(off), symIdx: si, kind: macho.mrUnsigned)

  # `dataConst` symbol-pointer fields (in __data): 8-byte UNSIGNED to the target.
  for it in a.rodataRebases:
    let si = defOf(it.target)
    if si >= 0:
      dataRels.add macho.MachORel(address: it.owner.size + it.blobOff,
                                  symIdx: si, kind: macho.mrUnsigned)

  let nDefined = syms.len  # everything added so far is defined; undefs come next

  # Undefined symbols: one per external proc (deduplicated by external name).
  var undefIndex = initTable[string, int]()
  proc undefOf(extName: string): int =
    result = undefIndex.getOrDefault(extName, -1)
    if result < 0:
      result = syms.len
      undefIndex[extName] = result
      syms.add macho.MachOSym(name: extName, defined: false)

  # External calls: the BL placeholder at each call site → BRANCH26 to the undef sym.
  for ext in a.extProcs:
    let si = undefOf(ext.extName)
    for cs in ext.callSites:
      textRels.add macho.MachORel(address: cs, symIdx: si, kind: macho.mrBranch26)

  # --- __data image: the whole globals region, with constant initializers baked ---
  # (Symbol-address slots stay zero; their relocations above supply the address.)
  var dataImage: seq[byte] = @[]
  if a.bssOffset > 0:
    dataImage = newSeq[byte](a.bssOffset)
    for it in a.bssInits:
      for i in 0 ..< it.size:
        if it.off.int + i < dataImage.len:
          dataImage[it.off.int + i] = byte((it.val shr (8 * i)) and 0xFF)

  macho.writeMachOObject(code, dataImage, syms, nDefined, textRels, dataRels,
                         cputype, cpusubtype, outfile)

proc writeExe(a: var GenContext; outfile: string) =
  fillTraceTable(a)
  finalize(a.buf)
  finalize(a.bssBuf)

  # Determine machine type based on architecture
  let machine =
    case a.arch
    of Arch.WinX64:
      pe.IMAGE_FILE_MACHINE_AMD64
    of Arch.WinA64:
      pe.IMAGE_FILE_MACHINE_ARM64
    else:
      pe.IMAGE_FILE_MACHINE_AMD64

  # Build dynlink info for external procs
  var dynlink: pe.DynLinkInfo
  for lib in a.imports:
    dynlink.libs.add pe.ImportedLibInfo(name: lib.name, ordinal: lib.ordinal)
  for ext in a.extProcs:
    dynlink.extProcs.add pe.ExternalProcInfo(
      name: ext.name, extName: ext.extName,
      libOrdinal: ext.libOrdinal, gotSlot: ext.gotSlot,
      callSites: ext.callSites)

  var labelPos = initTable[int, int]()
  for ld in a.buf.labels: labelPos[int(ld.id)] = ld.position

  # The `.data` image: every global's storage, with its statically known scalar
  # initializers already baked (`stdout = 1`, a string literal's bytes). Symbol
  # ADDRESS initializers can't be — they wait for the layout, below.
  var dataImage: seq[byte] = @[]
  if a.bssOffset > 0:
    dataImage = newSeq[byte](a.bssOffset)
    for it in a.bssInits:
      for i in 0 ..< it.size:
        if it.off.int + i < dataImage.len:
          dataImage[it.off.int + i] = byte((it.val shr (8 * i)) and 0xFF)

  # Every absolute pointer the patch below writes, so `.reloc` can list it and the
  # image survives being loaded away from its preferred base.
  var absSites: seq[pe.AbsSite] = @[]
  for it in a.bssSymInits:
    absSites.add pe.AbsSite(inData: true, pos: it.off.int)
  for it in a.rodataSymInits:
    if labelPos.hasKey(it.labelId):
      absSites.add pe.AbsSite(inData: false, pos: labelPos[it.labelId] + it.blobOff)

  # The patch hook below runs inside `writePE`, so it cannot capture the `var
  # GenContext` itself — take the site lists it needs (cheap ref-counted seqs) and a
  # pointer to the code buffer, all of which ARE capturable.
  let codeBuf = addr a.buf
  let gvarSites = a.gvarSites
  let bssSymInits = a.bssSymInits
  let rodataSymInits = a.rodataSymInits

  proc symVaddr(lay: pe.PeLayout; sym: Symbol): uint64 =
    ## The runtime address of `sym`: a proc/rodata label sits in `.text`, a global in
    ## `.data`. (The `.bss` byte offset of a global is kept in `sym.size`.)
    case sym.kind
    of skProc, skRodata:
      if labelPos.hasKey(sym.offset):
        lay.imageBase + lay.textRva.uint64 + labelPos[sym.offset].uint64
      else: 0'u64
    of skGvar: lay.imageBase + lay.dataRva.uint64 + sym.size.uint64
    else: 0'u64

  proc patchAddrs(lay: pe.PeLayout) =
    ## Bake every address that only the final layout determines. The ELF twin of this
    ## lives in `writeElf`; both are driven by the same three site lists.
    # Each global's RIP-relative `lea` placeholder: a 7-byte instruction with a disp32
    # at +3, relative to the address of the NEXT instruction.
    for (pos, sym) in gvarSites:
      let instrRva = lay.textRva + uint32(pos)
      let targetRva = lay.dataRva + uint32(sym.size)
      let disp = int32(int64(targetRva) - int64(instrRva + 7))
      for i in 0 ..< 4:
        codeBuf[].data[pos + 3 + i] = byte((disp shr (8 * i)) and 0xFF)
    # Function-pointer hooks (`gExitFlush = nimNoopFlush`) — an absolute address in a
    # global's slot; without this the slot stays zero and the indirect call jumps to 0.
    for it in bssSymInits:
      let v = symVaddr(lay, it.sym)
      for i in 0 ..< it.size:
        if it.off.int + i < dataImage.len:
          dataImage[it.off.int + i] = byte((v shr (8 * i)) and 0xFF)
    # The same, for an address embedded in a rodata blob (a vtable / RTTI record),
    # which lives in `.text` at its own label.
    for it in rodataSymInits:
      if not labelPos.hasKey(it.labelId): continue
      let sitePos = labelPos[it.labelId] + it.blobOff
      let v = symVaddr(lay, it.sym)
      for i in 0 ..< it.size:
        if sitePos + i < codeBuf[].data.len:
          codeBuf[].data[sitePos + i] = byte((v shr (8 * i)) and 0xFF)

  # The synthesized process entry, if any (see `setupWinEntry`); otherwise the image
  # starts at the first byte of `.text`, which is the entry proc.
  let entryOff = if a.winEntryOffset >= 0: a.winEntryOffset.uint32 else: 0'u32

  # `.pdata`/`.xdata` from the same per-proc facts the ELF path encodes as
  # `.eh_frame`. Win64 has no frame pointer either, so this is what lets the OS
  # unwind at all — a backtrace, and any future SEH, both hang off it.
  writePE(a.buf, dataImage, a.bssOffset, entryOff, machine, outfile, dynlink,
          absSites, patchAddrs, (if a.debugInfo: a.unwind else: @[]))


proc generateSymbol(ctx: var GenContext; sym: Symbol) =
  ## Generate code for a single reachable symbol on-demand. nifasm is the linker:
  ## a reachable FOREIGN symbol is bundled into this same output (its body/storage
  ## emitted, cross-module references resolved as ordinary direct relocations) —
  ## exactly like a local symbol, only the declaration is read from the foreign
  ## module's stream (at its indexed byte offset) instead of the main TokenBuf.
  if ctx.nameOf(sym.name) in ctx.generatedSymbols:
    return
  ctx.generatedSymbols.incl ctx.nameOf(sym.name)

  if sym.moduleName notin ctx.modules:
    return  # Module not loaded, can't generate

  let m = ctx.modules[sym.moduleName]
  var n: Cursor
  if sym.isForeign:
    n = getDecl(m.foreign, ctx.nameOf(sym.name), asmTags, ctx.pool)  # cached one-decl tree
  else:
    n = cursorAt(m.buf, sym.declStart)
  let declTag = tagToNifasmDecl(n.tag)

  case sym.kind
  of skProc:
    if declTag == ProcD:
      when defined(arkhamDbgSym):
        stderr.writeLine "DBG generateSymbol proc: " & ctx.nameOf(sym.name)
      pass2Proc(n, ctx)
  of skRodata:
    if declTag == RodataD:
      if ctx.arch == Arch.A64 and sym.dataConst:
        # Mach-O: a const whose fields are symbol addresses must be rebased by dyld,
        # which can only write a *writable* segment — so place it in __DATA (the .bss
        # image, like a statically-initialized gvar) rather than read-only __TEXT.
        # Its bytes go into the data image; each pointer field is recorded for a dyld
        # rebase (writeMachO bakes the preferred target vaddr and slides it at load).
        var rc = n                            # (rodata :name "str" (reloc off sym)*)
        into rc:
          skip rc                             # name (already have sym)
          let s = getStr(rc); skip rc
          # 8-align: pointer fields must be aligned for the load and for dyld's rebase.
          ctx.bssOffset = (ctx.bssOffset + 7) and not 7
          sym.size = ctx.bssOffset            # __DATA byte offset (for adrp+add)
          for i, ch in s:
            if ch != '\0':                    # zero bytes are already zero in the image
              ctx.bssInits.add (off: int64(sym.size + i), val: int64(ch), size: 1)
          ctx.bssOffset += s.len
          while rc.hasMore:
            var relc = rc
            into relc:
              let blobOff = getInt(relc); skip relc
              let tname = getSym(relc)
              let tsym = lookupWithAutoImport(ctx, ctx.scope, tname, relc)
              skip relc                       # past the target symbol
              if tsym != nil:
                ctx.rodataRebases.add (owner: sym, blobOff: blobOff.int, target: tsym)
            skip rc
      else:
        if sym.offset == -1:
          let labId = ctx.buf.createLabel()
          sym.offset = int(labId)
        ctx.buf.defineLabel(LabelId(sym.offset))
        var rc = n                            # (rodata :name "str" (reloc off sym)*)
        into rc:
          skip rc                             # name (already have sym)
          let s = getStr(rc); skip rc
          for ch in s: ctx.buf.data.add byte(ch)
          # Optional `(reloc off sym)` children: a field of this blob holds the
          # address of another symbol (vtable/RTTI). Mark the target reachable and
          # record the site so `writeElf` bakes its vaddr into the blob (in `.text`).
          while rc.hasMore:
            var relc = rc
            into relc:
              let blobOff = getInt(relc); skip relc
              let tname = getSym(relc)
              let tsym = lookupWithAutoImport(ctx, ctx.scope, tname, relc)
              skip relc                       # past the target symbol
              if tsym != nil:
                # One WORD, not a fixed eightbyte: arkham reserves exactly
                # `wordSize()` placeholder bytes for the field (see
                # `constToBytes`), and baking 8 over a 4-byte field overwrites
                # whatever follows it in the blob.
                ctx.rodataSymInits.add (labelId: sym.offset, blobOff: blobOff.int,
                                        sym: tsym, size: asmWordSize())
            skip rc
  of skGvar:
    if declTag == GvarD:
      # Allocate space in .bss section
      let size = slots.alignedSize(sym.typ)
      let align = asmSizeOf(sym.typ)
      if align > 1:
        ctx.bssOffset = (ctx.bssOffset + align - 1) and not (align - 1)
      let labId = ctx.bssBuf.createLabel()
      sym.offset = int(labId)
      sym.size = ctx.bssOffset      # byte offset within .bss (for arm64 adrp+add)
      ctx.bssBuf.defineLabel(labId)
      # A constant-scalar initializer (arkham emits its bits as the gvar's value
      # in `(gvar :name type value?)`): record it so writeElf writes the value into
      # the (writable) .bss image. `takeLocal` bounds the decl and exposes the
      # optional value via `hasVal`.
      var dn = n
      let lc = takeLocal(dn)
      if lc.hasVal and lc.val.kind == IntLit:
        ctx.bssInits.add (off: sym.size.int64, val: getInt(lc.val),
                          size: asmSizeOf(sym.typ))
      elif lc.hasVal and lc.val.kind == Symbol:
        # Symbol-address initializer (a function-pointer hook, or a gvar pointing
        # at another global). Resolve+mark the target (so its body/storage is
        # generated) and record the slot for address baking in writeElf.
        let initName = getSym(lc.val)
        let initSym = lookupWithAutoImport(ctx, ctx.scope, initName, lc.val)
        if initSym != nil:
          ctx.bssSymInits.add (off: sym.size.int64, sym: initSym,
                               size: asmSizeOf(sym.typ))
      elif lc.hasVal and lc.val.kind == StrLit:
        # An AGGREGATE constant initializer — an object/array constructor or a
        # string, laid out by arkham's `constToBytes` as the raw little-endian
        # bytes of the value. Fill the writable image byte-wise, exactly like a
        # `dataConst` rodata blob; zero bytes are already zero in the image.
        # Trailing `(reloc <off> <sym>)` children name the fields holding a
        # symbol ADDRESS, which only the final layout knows — same treatment as
        # the scalar symbol case above, one entry per field.
        let s = getStr(lc.val)
        for i, ch in s:
          if ch != '\0':
            ctx.bssInits.add (off: int64(sym.size + i), val: int64(ch), size: 1)
        var rc = n                            # (gvar :name type "bytes" (reloc …)*)
        into rc:
          skip rc                             # name
          skip rc                             # type
          skip rc                             # the byte blob
          while rc.hasMore:
            var relc = rc
            into relc:
              let blobOff = getInt(relc); skip relc
              let tname = getSym(relc)
              let tsym = lookupWithAutoImport(ctx, ctx.scope, tname, relc)
              skip relc                       # past the target symbol
              if tsym != nil:
                # One WORD, matching the placeholder arkham reserved — the same
                # rule as the rodata relocation above.
                ctx.bssSymInits.add (off: int64(sym.size) + blobOff, sym: tsym,
                                     size: asmWordSize())
            skip rc
      ctx.bssOffset += size
  of skTvar:
    if declTag == TvarD:
      let size = slots.alignedSize(sym.typ)
      case ctx.arch
      of Arch.A64:
        # macOS TLV: give the variable a descriptor index and a byte offset in
        # the per-thread storage region, and bake a literal initializer (if any)
        # into the __thread_data template dyld copies on first access per thread.
        let align = max(asmSizeOf(sym.typ), 1)
        while (ctx.tlvData.len mod align) != 0: ctx.tlvData.add 0
        sym.offset = ctx.tlvSyms.len    # descriptor index
        sym.size = ctx.tlvData.len      # byte offset within the per-thread region
        ctx.tlvSyms.add sym
        # Parse the optional initializer: (tvar :name type value?)
        var dn = n
        let lc = takeLocal(dn)
        var initVal = 0'i64
        if lc.hasVal and lc.val.kind == IntLit: initVal = getInt(lc.val)
        for i in 0 ..< size:
          ctx.tlvData.add byte((initVal shr (8 * i)) and 0xFF)
      else:
        allocTlsSlotX64(ctx, sym, n)
  else:
    discard  # Types and other symbols don't need code generation

proc processReachableSymbols(ctx: var GenContext) =
  ## Process all pending symbols until queue is empty
  while ctx.pendingSymbols.len > 0:
    let fullName = ctx.pendingSymbols.pop()
    if fullName in ctx.generatedSymbols:
      continue

    # Handle deduplication
    let canonicalName = getCanonicalName(ctx, fullName)
    if canonicalName != fullName and canonicalName in ctx.generatedSymbols:
      continue  # Already generated the canonical version

    # Find the symbol by its full qualified name (nominal identity).
    let sym = ctx.scope.lookup(ctx.symIdOf(fullName))
    if sym != nil:
      generateSymbol(ctx, sym)

proc setupWinEntry(ctx: var GenContext) =
  ## Synthesize the PE entry stub — the Windows counterpart of `setupTls`'s prologue.
  ##
  ## arkham's `main.0` has the C signature `main(argc, argv, envp)` and reads those
  ## three from its argument registers, which on Linux the entry prologue fills from
  ## the stack block the kernel hands over. Windows hands the entry point NOTHING:
  ## the command line is fetched from `GetCommandLineW`, and every register is
  ## undefined. So zero them — `paramCount()` then reports no arguments rather than
  ## `main` storing garbage into `cmdCount`/`cmdLine`/`nimEnviron` and every later
  ## `paramStr` walking a wild pointer. (Wiring the real command line through
  ## `GetCommandLineW` + `CommandLineToArgvW` is a separate step.)
  if ctx.arch != Arch.WinX64 or ctx.entrySym == nil: return
  ctx.winEntryOffset = ctx.buf.data.len
  x86.emitMovImmToReg(ctx.buf.data, x86.RDI, 0)             # argc = 0
  x86.emitMovImmToReg(ctx.buf.data, x86.RSI, 0)             # argv = nil
  x86.emitMovImmToReg(ctx.buf.data, x86.RDX, 0)             # envp = nil
  x86.emitJmp(ctx.buf, LabelId(ctx.entrySym.offset))        # → real entry

proc setupLinuxA64Entry(ctx: var GenContext) =
  ## Synthesize the AArch64/Linux entry stub — the counterpart of `setupTls`'s
  ## argc/argv tail on x86-64.
  ##
  ## arkham's `main.0` has the C signature `main(argc, argv, envp)` and reads the
  ## three from x0/x1/x2 straight into the `cmdCount`/`cmdLine`/`nimEnviron` globals
  ## that `std/cmdline` and `std/envvars` are built on. The kernel does NOT put them
  ## in registers: at process entry SP points at the argument block — argc is the
  ## word at [sp], argv[0] follows at [sp+8] — and the registers are undefined. With
  ## no stub the ELF entry was `main.0` itself, so `cmdCount` took whatever x0 held
  ## and `paramCount()` reported -1 (argc 0 ⇒ count = argc-1).
  ##
  ## Unlike x86-64 this is unconditional: AArch64 needs no TLS prologue to hang the
  ## argument setup off, so the stub exists purely for this.
  if ctx.arch != Arch.LinuxA64 or ctx.entrySym == nil: return
  # Same 4-alignment rule as a proc body (see `pass2Proc`): the stub is appended
  # to a `.text` whose last bytes are a lazily emitted rodata blob of arbitrary
  # length, and the ELF entry must land on an instruction boundary or the very
  # first `ldr` takes SIGBUS.
  while (ctx.buf.data.len and 3) != 0: ctx.buf.data.add 0'u8
  ctx.entryStubOffset = ctx.buf.data.len
  arm64.emitLdr(ctx.buf.data, arm64.X0, arm64.SP, 0'i32)      # x0 = argc
  arm64.emitAddImm(ctx.buf.data, arm64.X1, arm64.SP, 8'u16)   # x1 = &argv[0]
  # envp sits past argv[0..argc-1] and its NULL terminator, i.e. at &argv[argc+1]:
  # `x2 = x1 + 8*argc + 8`. argc is a full 64-bit word on the stack even though
  # `main` types it `(i 32)`, so the shifted add is exact.
  arm64.emitAddShifted(ctx.buf.data, arm64.X2, arm64.X1, arm64.X0, 3'u8)
  arm64.emitAddImm(ctx.buf.data, arm64.X2, arm64.X2, 8'u16)   # x2 = &envp[0]
  arm64.emitB(ctx.buf, LabelId(ctx.entrySym.offset))          # → real entry

proc setupTls(ctx: var GenContext) =
  ## nifasm owns the per-thread TLS. After every bundled tvar has an FS offset
  ## (`ctx.tlsOffset`), reserve the unified `arkham.tls.0` block in `.bss` (sized
  ## for all modules' tvars) and synthesize the entry prologue that points FS at it
  ## via `arch_prctl(ARCH_SET_FS, &arkham.tls.0)`, then jumps to the real entry.
  ## Nim thread-locals have no initializers, so the block is just zeroed `.bss`.
  ## x86-64 only (AArch64 TLS uses a different mechanism, not yet implemented).
  const ArchSetFs = 0x1002      # arch_prctl(2) ARCH_SET_FS
  const ArchPrctlNr = 158       # x86-64 syscall number for arch_prctl
  if ctx.arch != Arch.X64 or ctx.tlsOffset == 0: return
  if ctx.tlsBlockSym == nil or ctx.entrySym == nil: return
  # Reserve the per-thread block in .bss (16-byte aligned); its address is the FS
  # base, and every tvar lives at `FS:[its offset]` within it.
  ctx.bssOffset = (ctx.bssOffset + 15) and not 15
  ctx.tlsBlockSym.size = ctx.bssOffset
  ctx.bssOffset += (ctx.tlsOffset + 15) and not 15
  # Now that the block has its `.bss` offset, every tvar's literal initializer is at
  # a known image address: bake it in like a gvar's (`allocTlsSlotX64`).
  for it in ctx.tlsInits:
    ctx.bssInits.add (off: int64(ctx.tlsBlockSym.size) + it.off, val: it.val,
                      size: it.size)
  # Synthesize the FS-setup prologue at the end of .text — it becomes the ELF entry
  # (see writeElf) and tail-jumps to the program's real entry proc.
  ctx.entryStubOffset = ctx.buf.data.len
  let pos = x86.emitLeaRipPlaceholder(ctx.buf, x86.RSI)     # lea rsi, [rip+arkham.tls.0]
  ctx.gvarSites.add (pos, ctx.tlsBlockSym)
  x86.emitMovImmToReg(ctx.buf.data, x86.RDI, ArchSetFs)
  x86.emitMovImmToReg(ctx.buf.data, x86.RAX, ArchPrctlNr)
  x86.emitSyscall(ctx.buf.data)                             # arch_prctl(ARCH_SET_FS, &block)
  # Hand the kernel-provided argc/argv to `main(argc, argv)` the way a C crt0 would.
  # At process entry the SysV ABI puts argc at [rsp] and argv[0] at [rsp+8] (NOT in
  # rdi/rsi — the kernel zeroes the registers), and the prologue above leaves rsp
  # untouched. main's full signature takes argc in rdi (param 0) and argv in rsi
  # (param 1); without this they were garbage, so `cmdCount`/`cmdLine` stayed 0 and
  # `paramCount()` returned -1 (every `paramStr` was empty).
  x86.emitMov(ctx.buf.data, x86.RDI, x86.MemoryOperand(base: x86.RSP))            # rdi = argc
  x86.emitLea(ctx.buf.data, x86.RSI, x86.MemoryOperand(base: x86.RSP, displacement: 8'i32))  # rsi = &argv[0]
  # main's 3rd arg (rdx) = the environment block. After argv[0..argc-1] and the NULL
  # terminator, the kernel lays out `envp` at `&argv[argc+1]`. With rdi=argc and
  # rsi=&argv[0]: `envp = rsi + 8*(argc+1) = rsi + 8*argc + 8`. (genMainProc stores
  # this into the `nimEnviron` global; std/envvars + std/posix read it under
  # `-d:nimNativeIo`, matching how rsi feeds `cmdLine`.)
  x86.emitLea(ctx.buf.data, x86.RDX, x86.MemoryOperand(base: x86.RSI, index: x86.RDI,
                                                       scale: 8, displacement: 8'i32, hasIndex: true))  # rdx = &envp[0]
  x86.emitJmp(ctx.buf, LabelId(ctx.entrySym.offset))        # → real entry

proc writeCortexMImage(a: var GenContext; code: seq[byte];
                       entryOff: int): seq[byte] =
  ## The finished firmware: a vector table plus code at the flash base, and the
  ## globals as a second segment in SRAM.
  ##
  ## `.bss` is emitted FILE-BACKED (filesz == memsz) rather than as a NOBITS
  ## region. That costs image size but is correct everywhere: a NOBITS segment
  ## relies on the loader zeroing it, which QEMU's `-kernel` does and a real chip
  ## emphatically does not — real firmware zeroes `.bss` in its reset handler,
  ## and that startup code is M6's business. Baking the bytes means the two
  ## behave identically until then.
  finalize(a.bssBuf)
  var bssImage: seq[byte] = @[]
  if a.bssOffset > 0:
    bssImage = newSeq[byte](a.bssOffset)
    for it in a.bssInits:
      for i in 0 ..< it.size:
        if it.off.int + i < bssImage.len:
          bssImage[it.off.int + i] = byte((it.val shr (8 * i)) and 0xFF)

  let bssVaddr = elf32.SramBase
  let codeVaddr = elf32.FlashBase
  # A global initialized with another SYMBOL's address — `var hook = twice`, `var
  # alias = addr counter` — is a relocation, not a constant, so it is baked here
  # once every label has a position. Without this the cell stays zero and the
  # first indirect call through it branches to address 0; the failure is a
  # lockup with nothing at the crash site to say which global was never filled.
  #
  # A proc's address carries the Thumb bit, for the same reason `rkTMovwMovtFunc`
  # does: `blx` to an even address asks for ARM state, which M-profile has none of.
  if a.bssSymInits.len > 0 and bssImage.len > 0:
    var labelPos = initTable[int, int]()
    for ld in a.buf.labels: labelPos[int(ld.id)] = ld.position
    let codeBase = codeVaddr + uint32(elf32.VectorTableSize)
    for it in a.bssSymInits:
      var targetVaddr = 0'u32
      case it.sym.kind
      of skProc:
        if not labelPos.hasKey(it.sym.offset): continue
        targetVaddr = codeBase + uint32(labelPos[it.sym.offset]) + 1'u32
      of skRodata:
        if not labelPos.hasKey(it.sym.offset): continue
        targetVaddr = codeBase + uint32(labelPos[it.sym.offset])
      of skGvar:
        targetVaddr = bssVaddr + uint32(it.sym.size)
      else: continue
      for i in 0 ..< it.size:
        if it.off.int + i < bssImage.len:
          bssImage[it.off.int + i] = byte((targetVaddr shr (8 * i)) and 0xFF)

  # The stack grows DOWN from `DefaultStackTop`, the globals UP from `SramBase`.
  # They share one RAM region, so say so when they would meet rather than letting
  # the first deep call frame quietly overwrite a global.
  if bssVaddr + uint32(a.bssOffset) >= elf32.DefaultStackTop:
    quit "nifasm: " & $a.bssOffset & " bytes of globals would reach the stack at 0x" &
         toHex(elf32.DefaultStackTop, 8)

  var patched = code

  # Bake the symbol-address fields of a rodata blob — a vtable, an RTTI record, a
  # `const` holding `addr other` — now that every label has a position. The blob
  # lives in the code segment at its own label; each recorded field is a 4-byte
  # ABSOLUTE address, and a proc's carries the Thumb bit for the same reason
  # `rkTMovwMovtFunc` does: a function pointer read out of a table is called
  # through `blx` like any other.
  if a.rodataSymInits.len > 0:
    var labelPos = initTable[int, int]()
    for ld in a.buf.labels: labelPos[int(ld.id)] = ld.position
    for it in a.rodataSymInits:
      if not labelPos.hasKey(it.labelId): continue
      let sitePos = labelPos[it.labelId] + it.blobOff
      var targetVaddr = 0'u32
      case it.sym.kind
      of skProc:
        if labelPos.hasKey(it.sym.offset):
          targetVaddr = codeVaddr + uint32(elf32.VectorTableSize) +
                        uint32(labelPos[it.sym.offset]) + 1'u32   # Thumb bit
      of skRodata:
        if labelPos.hasKey(it.sym.offset):
          targetVaddr = codeVaddr + uint32(elf32.VectorTableSize) +
                        uint32(labelPos[it.sym.offset])
      of skGvar:
        targetVaddr = bssVaddr + uint32(it.sym.size)
      else: discard
      for i in 0 ..< it.size:
        if sitePos + i < patched.len:
          patched[sitePos + i] = byte((targetVaddr shr (8 * i)) and 0xFF)

  # Patch every `(adr D <gvar>)` / indirect-call MOVW+MOVT pair with the global's
  # absolute address, now that the .bss layout is fixed. `sym.size` is its byte
  # offset within .bss — the same field the ELF64 and Mach-O backends read.
  for (pos, sym) in a.gvarSites:
    if pos + 8 > patched.len: continue
    var bytes = initBytes()
    for i in 0 ..< 8: bytes.add patched[pos + i]
    bytes.patchThumbMovwMovtPair(0, bssVaddr + uint32(sym.size))
    for i in 0 ..< 8: patched[pos + i] = bytes[i]

  var image = elf32.initVectorTable(elf32.DefaultStackTop,
                              codeVaddr + uint32(elf32.VectorTableSize + entryOff))
  image.add patched
  var segs = @[elf32.Segment(vaddr: codeVaddr, data: image, memSize: image.len,
                       flags: elf32.PF_R or elf32.PF_W or elf32.PF_X)]
  if bssImage.len > 0:
    segs.add elf32.Segment(vaddr: bssVaddr, data: bssImage, memSize: bssImage.len,
                     flags: elf32.PF_R or elf32.PF_W)
  result = elf32.writeElf32(segs, codeVaddr + uint32(elf32.VectorTableSize + entryOff))

proc assemble*(filename, outfile: string; symMap = false; emitObj = false;
               listing = ""; debugInfo = true) =
  var buf = parseFromFile(filename, sharedTags = asmTags)
  # The main module's pool is shared with every foreign module (getDecl is passed
  # `ctx.pool`), so a `SymId` from ANY cursor is a valid key in the one scope table.
  # Captured before the `move buf` below so the ref keeps the pool alive regardless.
  let mainPool = buf.pool

  # Extract base directory from filename
  let baseDir = filename.splitFile.dir
  # The module being assembled — its symbol suffix (e.g. `foo.asm.nif` → "foo"), so a
  # `name.0.foo` reference resolves to a local definition instead of a foreign import.
  let thisModule = extractModuleSuffix(filename)

  var scope = newScope()

  # Create a minimal ctx for pass1 (for foreign module loading)
  var ctx = GenContext(
    scope: scope,
    rootScope: scope,
    buf: initBuffer(),
    bssBuf: initBuffer(),
    tlsOffset: 0,
    bssOffset: 0,
    modules: initTable[string, LoadedModule](),
    pool: mainPool,
    baseDir: baseDir,
    thisModule: thisModule,
    imports: @[],
    extProcs: @[],
    gotSlotCount: 0,
    pendingSymbols: @[],
    generatedSymbols: initHashSet[string](),
    dedupTable: initTable[string, string](),
    entryStubOffset: -1,
    winEntryOffset: -1,
    symMap: symMap,
    listing: listing.len > 0,
    listingPath: listing,
    emitObj: emitObj,
    debugInfo: debugInfo
  )

  # Store main module. `beginRead` BEFORE the move forces the buffer's
  # CursorOwner into existence, which takes a tracked ref on its pool/tags. The
  # move's `=wasMoved` ARC-decrements the moved-from buffer's `pool`; without the
  # owner's ref that would free a pool no cursor yet protects (the classic
  # "beginRead-after-move" heap bug, see [[reindex-tool]]).
  discard beginRead(buf)
  ctx.modules[MainModuleName] = LoadedModule(buf: move buf, loaded: true)

  # The unified per-thread TLS block is owned by nifasm, not any single module
  # (arkham only references it for `&tvar`/`FS:[off]`). Define it up front so those
  # references resolve; it's pre-marked generated (nifasm sizes + allocates it in
  # `setupTls` once all bundled tvars are known) and FS is set in the entry prologue.
  ctx.tlsBlockSym = Symbol(name: ctx.symIdOf("arkham.tls.0"), kind: skGvar,
                           typ: Type(kind: UIntT, bits: 8), offset: -1)
  scope.define(ctx.tlsBlockSym)
  ctx.generatedSymbols.incl "arkham.tls.0"

  # Same treatment for the stack-trace table's label: nifasm owns the data, so it
  # owns the symbol. Defining it up front is what lets `lea D, (lab arkham.traceinfo.0)`
  # resolve like any other label instead of sending `lookupWithAutoImport` off to
  # look for a module named `traceinfo`. Its LabelId is created after the pass-2
  # buffer reset below (the reset restarts label numbering).
  ctx.traceSym = Symbol(name: ctx.symIdOf(TraceInfoSymbol), kind: skLabel, offset: -1)
  scope.define(ctx.traceSym)
  ctx.generatedSymbols.incl TraceInfoSymbol

  var n1 = beginRead(ctx.modules[MainModuleName].buf)
  pass1(n1, scope, ctx, MainModuleName, ctx.modules[MainModuleName].buf)

  # x86-64: a thread-local is read/written as `FS:[sym.offset]` with the
  # displacement baked at the *reference* site (no relocation), so every tvar's
  # offset must be fixed before any code is generated — otherwise a reference
  # compiled before the tvar's lazy `generateSymbol` would capture the default 0.
  # (macOS/A64 resolves tvars through relocated descriptors and allocates lazily.)
  if ctx.arch == Arch.X64:
    var tn = beginRead(ctx.modules[MainModuleName].buf)
    if tn.kind == TagLit and tn.tag == StmtsTagId:
      loopInto tn:
        if tn.kind == TagLit and tagToNifasmDecl(tn.tag) == TvarD:
          let start = tn
          inc tn                              # tvar tag
          if tn.kind == SymbolDef:
            let sym = scope.lookup(getSymId(tn))
            if sym != nil and sym.kind == skTvar and ctx.nameOf(sym.name) notin ctx.generatedSymbols:
              allocTlsSlotX64(ctx, sym, start)
              ctx.generatedSymbols.incl ctx.nameOf(sym.name)   # don't re-allocate in generateSymbol
          tn = start
        skip tn

  # Update ctx with proper buffers for pass2
  ctx.buf = initBuffer()
  ctx.bssBuf = initBuffer()
  ctx.traceLabel = ctx.buf.createLabel()
  ctx.traceSym.offset = int(ctx.traceLabel)

  # Generate code for entry point (top-level instructions only)
  # This marks symbols as used via lookupWithAutoImport when they are referenced
  var n = beginRead(ctx.modules[MainModuleName].buf)
  pass2(n, ctx)

  # Process all pending symbols (both main module and foreign modules)
  # This generates code only for symbols that were actually referenced (dead code elimination)
  processReachableSymbols(ctx)

  # Now that every bundled tvar has an FS offset, reserve the unified TLS block and
  # synthesize the per-target entry stub: the FS base (x86-64), zeroed arguments
  # (Windows), the kernel's argument block (AArch64/Linux). At most one applies.
  appendTraceTable(ctx)
  setupTls(ctx)
  setupWinEntry(ctx)
  setupLinuxA64Entry(ctx)

  if ctx.emitObj:
    # Relocatable object for the system linker (foreign `.o` / framework linking).
    # Standalone executable emission below is unaffected.
    case ctx.arch
    of Arch.A64:
      writeMachOObject(ctx, outfile)
    else:
      quit "nifasm: --emit-obj is only supported for macOS arm64"
  else:
    case ctx.arch
    of Arch.X64, Arch.LinuxA64:
      writeElf(ctx, outfile)
    of Arch.A64:
      writeMachO(ctx, outfile)
    of Arch.WinX64, Arch.WinA64:
      writeExe(ctx, outfile.changeFileExt("exe"))
    of Arch.CortexM:
      # A firmware image, not a hosted executable: vector table, then code.
      #
      # `absBase` is what makes the MOVW+MOVT absolute relocations correct: those
      # carry a label's real ADDRESS, and the code is loaded 8 bytes above the
      # image base because the vector table sits there. Without it every
      # `(adr …)` would resolve 8 bytes low — near enough to look plausible and
      # read the wrong bytes.
      ctx.buf.absBase = elf32.FlashBase + uint32(elf32.VectorTableSize)
      finalize(ctx.buf)
      var code: seq[byte] = newSeq[byte](ctx.buf.data.len)
      for i in 0 ..< ctx.buf.data.len: code[i] = ctx.buf.data[i]
      # The reset vector points at the ENTRY PROC, not at the first byte emitted.
      # Those coincide today only because `pass2` generates `_start`/`main.0`
      # eagerly the moment it sees it; nothing guarantees that, and a wrong reset
      # vector starts executing some other proc's prologue with no diagnostic.
      # A module of bare top-level statements has no entry symbol, and there 0 is
      # genuinely right.
      var entryOff = 0
      if ctx.entrySym != nil:
        let pos = ctx.buf.getLabelPosition(LabelId(ctx.entrySym.offset))
        if pos < 0:
          quit "nifasm: entry point '" & ctx.nameOf(ctx.entrySym.name) &
               "' has no address"
        entryOff = pos
      writeFile(outfile, writeCortexMImage(ctx, code, entryOff))

  # Close all foreign-module readers (the main module has no reader).
  for modname, module in ctx.modules.mpairs:
    if modname != MainModuleName and module.foreign != nil:
      nifreader.close(module.foreign.r)
