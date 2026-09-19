#
#           The web back end — Leng → JavaScript / wasm32
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## The ONE code generator of both web targets: Leng in, the web IR of
## `webnif` out, plus the `WebModule` facts that are not code (the static
## image, the function table, the host imports, the entry point). `jsrender`
## prints the result as JavaScript, `wasmrender` as a wasm32 binary; nothing
## here depends on which of the two runs.
##
## The generator is whole-program: starting from the entry proc (and every
## other `exportc` proc of the main module) it pulls every reachable
## declaration across modules through arkham's lazy foreign-module loader.
##
## It owns linear memory: it decides where every global and every read-only
## blob lives and turns compile-time initializers into bytes at those absolute
## addresses. Leng already gives every object an explicit layout, so there are
## no relocations: an address-valued field of a constant (a string's `data`
## pointer, a `(addr g)` initializer, a proc symbol in an RTTI method table) is
## a FIXUP resolved here, while the whole program's layout is in this module's
## hands.
##
## The value model: a ≤32-bit integer, a pointer and a float are scalars that
## live in function locals; a 64-bit integer too (a `BigInt` in JavaScript, an
## `i64` in wasm). An aggregate, and any local whose address is taken, lives in
## linear memory — a global at its static address, a local in the function's
## shadow-stack frame — and its "value" is its address, exactly as in C.

import std / [tables, sets, strutils, assertions, algorithm]
import nifcore, nifcdecl
import webnif
import "../arkham/core" / [asmslots, programs, typenav, typeutil]

const
  WebPtrSize* = 4
  NullGuard* = 1024'u32     ## below this stays untouched, so a null deref
                            ## reads zeros instead of the static data
  ShadowStackSize* = 1 shl 20

type
  ScalKind* = enum skI32, skI64, skF32, skF64, skMem
  Scal* = object
    kind*: ScalKind
    bits*: int              ## source-level width (8/16/32/64); Mem: byte size
    signed*: bool

  LocalKind = enum
    lkReg                         ## a scalar: lives in a function local
    lkSlot                        ## a value in the frame, at `fp + off`
    lkPtr                         ## an aggregate PARAM: the argument already
                                  ## holds its address, so no slot is needed

  LocalSlot = object
    kind: LocalKind
    off: int                      ## lkSlot: byte offset from the frame base
    taken: bool                   ## `(addr :name)` occurs in the body

  TempSlot = object
    off: int                      ## byte offset of a materialized value
    size: int                     ## what it holds, so a plan mismatch is caught

  ProcCtx = object
    irName: SymId                 ## the IR function's name, in the IR pool
    symType: Table[string, Cursor] ## local/param name → its Leng type
    locals: Table[string, LocalSlot]
    retType: Cursor
    sret: bool                    ## the result is an aggregate: hidden dest arg
    sretName: SymId               ## IR name of that hidden parameter
    frameSize: int                ## shadow-stack bytes; 0 needs no frame at all
    fp: SymId                     ## IR name of the frame base, when frameSize > 0
    tmpPlan: seq[TempSlot]        ## materializations, in preorder
    tmpAt: int                    ## how many codegen has consumed
    tmp: int                      ## per-proc temporary counter
    labs: seq[SymId]              ## open `(lab)` label blocks, innermost last
                                  ## (IR names: a Leng label and a generated
                                  ## join block are both just blocks here)
    regLocals: seq[string]        ## `lkReg` locals, in declaration order
    temps: seq[(SymId, WidthCode)] ## generator temporaries, declared with the locals

  WebGen* = object
    prog*: Program
    tags*: TagPool                ## the Leng tag pool `buf` was parsed with
    lengPool*: Pool               ## the Leng LITERALS pool: `SymId`s below that
                                  ## name a Leng symbol live here
    irPool: Pool                  ## the web IR's own pool: every `SymId` that
                                  ## names something in the emitted tree
    outp*: TokenBuf               ## the body of the function being lowered — the
                                  ## web IR pool, never the Leng one
    top*: TokenBuf                ## the `(top FUNC*)` program: finished functions
    callTarget: Table[string, CallTarget] ## typenav needs a mutable copy
    globals: Table[string, Cursor]        ## name → gvar/const decl (foreign ones cached on use)
    tvars: Table[string, Cursor]
    memTop*: uint32                    ## static-data bump pointer
    globalAddr*: Table[SymId, uint32]    ## CANONICAL symbol → address (see `globalAddrOf`)
    canonDecl: Table[SymId, Cursor]      ## canonical symbol → the decl to serialize (a C-linkage
                                         ## pair resolves through whichever name came first)
    staticsDone: HashSet[SymId]          ## canonical symbols whose static init is in `dataSegs`
    rodataAddr: Table[string, uint32]  ## string literal → address (deduped)
    dataSegs*: seq[(uint32, string)]
    allocLog: seq[(uint32, uint32, string)] ## (addr, size, owner) for the overrun check
    tableSlot: Table[SymId, uint32]    ## proc symbol → function-table index (0 is null)
    nextTableSlot: uint32
    tableEntries: seq[SymId]           ## slot i (from 1) → the proc symbol bound there
    pending: seq[(SymId, Cursor)]      ## reachable procs not yet lowered
    emitted: HashSet[SymId]
    irNameOf: Table[SymId, SymId]      ## Leng symbol → its name in the IR pool
    usedNames: HashSet[string]         ## every IR name SPELLING handed out: the
                                       ## mangling is what can collide, so this
                                       ## one set really is about text
    p: ProcCtx                         ## the proc being lowered
    entrySym*: SymId
    target*: WebTarget
    hostImports*: bool                 ## a bodyless `importc` proc is a host import
                                       ## (an `env` function the page provides)
                                       ## instead of a refusal
    imports*: seq[WebImport]           ## the host floor, then discovered host imports
    importOf: Table[string, SymId]     ## importc C name → its import's IR name
    thunks: seq[(SymId, SymId, Cursor)] ## (thunk symbol, proc symbol, decl):
                                       ## closure-signature bridges to lower
    needMemcmp: bool                   ## the synthetic `memcmp` is referenced
    tmpNames: seq[SymId]               ## `n_tmp_1`, `n_tmp_2`, … minted once and
                                       ## REUSED by every proc: a local is scoped
                                       ## to its function on both targets
    impWrite, impExit: SymId           ## the host floor and the flag registers,
    globErrv, globOvf: SymId           ## interned once: the tree names them often
    memcmpFn: SymId
    callbacks: seq[string]             ## JS wrapper functions bridging a JS callback
                                       ## call to a Nim proc whose args/result need
                                       ## the handle/string bridge (emitted at the tail)

  WebTarget* = enum
    wtJs                               ## JavaScript: `importjs` splices are legal
    wtWasm                             ## wasm32

type
  WebGenError* = object of CatchableError
    ## A program the generator does not understand. This is an ordinary
    ## failure, not a broken invariant: the CLI reports it as one line and the
    ## coverage harness can ask "can you generate this?" without dying. An
    ## assertion here would be fatal — `--panics` off makes a `Defect`
    ## uncatchable — so a refusal must never be one.

proc err(g: WebGen; msg: string) {.noreturn.} =
  raise (ref WebGenError)(msg: msg)

proc lengSym(g: var WebGen; name: string): SymId {.inline.} =
  ## A Leng symbol's pool id from its spelling — the boundary where `core`'s
  ## name-keyed queries (`lookupSym`, `gvarRefName`) meet the id-keyed tables
  ## here.
  g.lengPool.syms.getOrIncl(name)

proc typeCtx(g: var WebGen): TypeCtx =
  TypeCtx(prog: addr g.prog, callTarget: addr g.callTarget,
          globals: addr g.globals, tvars: addr g.tvars,
          symType: addr g.p.symType)

proc scalOf(g: var WebGen; t: Cursor): Scal =
  ## The computation class of a Leng type: how wide and how signed the SOURCE
  ## type is, and whether it travels in memory rather than in a value.
  let s = slotOf(g.prog, t)
  case s.kind
  of AFloat:
    if s.size == 4: Scal(kind: skF32, bits: 32) else: Scal(kind: skF64, bits: 64)
  of AMem: Scal(kind: skMem, bits: s.size)
  of ABool: Scal(kind: skI32, bits: 8, signed: false)
  of AInt, AUInt:
    let signed = s.kind == AInt
    if s.size == 8: Scal(kind: skI64, bits: 64, signed: signed)
    else: Scal(kind: skI32, bits: s.size * 8, signed: signed)

# ── linear memory layout ─────────────────────────────────────────────────────

proc alignUp(x: uint32; a: uint32): uint32 = (x + a - 1) and not (a - 1)

proc isPtrType(g: var WebGen; t: Cursor): bool =
  let r = resolveType(g.prog, t)
  r.kind == TagLit and r.typeKind in {PtrT, AptrT}

proc isNimStringType(g: var WebGen; t: Cursor): bool =
  ## A Nim `string` — the `string.0.<system>` symbol (Leng has no builtin type
  ## kind for it). Its value is the 8-byte SSO struct; the splice decodes it to
  ## a JS string (§6). Checked on the type cursor before it is resolved, which
  ## would fold the symbol to its `(object bytes more)` definition and lose the name.
  t.kind == Symbol and symName(t).startsWith("string.0.")

proc isCstringType(g: var WebGen; t: Cursor): bool =
  ## A `cstring` is `(aptr char)` in Leng — a pointer to NUL-terminated bytes,
  ## NOT a JS handle. It must be recognised before the pointer/handle case,
  ## which isPtrType would otherwise swallow it into.
  t.kind == TagLit and t.typeKind == AptrT and
    (let inner = innerType(g.prog, t); inner.kind == TagLit and inner.typeKind == CT)

proc isProctypeType(g: var WebGen; t: Cursor): bool =
  ## A function type — possibly under one `(ptr …)` layer — where a `ref object`
  ## handle would otherwise catch it. In a splice a proctype operand is a Nim
  ## proc handed to a JS API as a callback (rAF, setTimeout, a DOM listener).
  var r = resolveType(g.prog, t)
  if r.kind == TagLit and r.typeKind in {PtrT, AptrT}:
    var inner = r
    inc inner
    r = resolveType(g.prog, inner)
  r.kind == TagLit and r.typeKind == ProctypeT

type
  JsBridgeKind = enum jbNone, jbString, jbCstring, jbHandle, jbCallback

proc jsBridgeKind(g: var WebGen; t: Cursor): JsBridgeKind =
  ## How a type crosses an `importjs` splice boundary, in precedence order: a
  ## Nim `string` (decode the SSO struct), a `cstring` (NUL-terminated bytes),
  ## a proctype (a Nim proc used as a JS callback), then any other pointer/ref as
  ## a JS HANDLE — an opaque int32 index into the host value table (plan §6): a
  ## binding declares a JS object (`GPUBuffer`, a canvas context, …) as an opaque
  ## `ref object`/pointer and touches it only through `importjs`, so at the splice
  ## it unwraps to the real JS value and a pointer result wraps back to a handle.
  ## Confined to splices — ordinary Nim pointers stay real addresses, because a JS
  ## API never takes a linear-memory address. Scalars and plain aggregates are
  ## jbNone and pass through untouched.
  if isNimStringType(g, t): jbString
  elif isCstringType(g, t): jbCstring
  elif isProctypeType(g, t): jbCallback
  elif isPtrType(g, t): jbHandle
  else: jbNone

proc isVoidType(t: Cursor): bool =
  t.kind == DotToken or (t.kind == TagLit and t.typeKind == VoidT)

proc isAggType(g: var WebGen; t: Cursor): bool =
  ## A DotToken is the ABSENCE of a type — a void result, an elided field type.
  ## It has no size to ask for, so it is not an aggregate. The spelled `(void)`
  ## is the same absence (ithaqua's sret test checks `isVoidType` first for
  ## exactly this reason): a void result returns nothing, it does not sret a
  ## zero-byte object.
  if t.kind == DotToken: return false
  if t.kind == TagLit and t.typeKind == VoidT: return false
  scalOf(g, t).kind == skMem

proc byteSize(g: var WebGen; t: Cursor): int =
  let (sz, _) = typeSizeAlign(g.prog, t)
  sz

proc byteAlign(g: var WebGen; t: Cursor): int =
  ## A FRAME slot's alignment. `stackSlotAlign` and `typeSizeAlign` differ on
  ## purpose: a 16-byte array is align 8 as a type — its elements are — but
  ## align 16 as a stack slot. Everything here is a stack slot. The floor of 8
  ## is what makes a slot a valid home for a pointer or an i64 in a 32-bit
  ## target's world of 4-byte scalars.
  max(stackSlotAlign(g.prog, t), 8)

proc elemTypeOf(g: var WebGen; arrType: Cursor): Cursor =
  innerType(g.prog, resolveType(g.prog, arrType))


proc allocStatic(g: var WebGen; size, align: int; tag = ""): uint32 =
  g.memTop = alignUp(g.memTop, uint32(max(align, 1)))
  result = g.memTop
  g.memTop += uint32(max(size, 1))
  g.allocLog.add (result, uint32(max(size, 1)), tag)

proc flexPayloadLen(g: var WebGen; initv: Cursor): int =
  ## Extra bytes a constant initializer stores past its type's fixed size:
  ## the payload of a flexarray tail (a string literal or an array
  ## constructor). +1 for a string's NUL so C-string views stay valid.
  result = 0
  if initv.kind != TagLit or initv.exprKind notin {OconstrC, AconstrC}: return
  if initv.exprKind == AconstrC:
    # A TOP-LEVEL flexarray/method-table const (`(aconstr T elem…)`): the
    # whole payload is elements — same element-type convention as the kv
    # case below / serializeConstInto.
    var ac = initv
    ac.into:
      let arrT = resolveType(g.prog, ac)
      var esz: int
      if arrT.kind == TagLit and arrT.typeKind in {PtrT, AptrT}:
        esz = WebPtrSize
      else:
        let elemT = innerType(g.prog, arrT)
        (esz, _) = typeSizeAlign(g.prog, elemT)
      skip ac
      var n = 0
      while ac.hasMore: (inc n; skip ac)
      result += n * esz
    return
  var t = initv
  t.into:
    skip t                                     # the constructed type
    while t.hasMore:
      if t.kind == TagLit and t.substructureKind == KvU:
        var kv = t
        kv.into:
          inc kv                               # field name
          if kv.kind == StrLit:
            result += strVal(kv).len + 1
          elif kv.kind == TagLit and kv.exprKind == AconstrC:
            # Elements × element size, with the same container convention as
            # `serializeConstInto`: an array/flexarray type gives the element
            # via `innerType`, a bare pointer container (hexer's fixed method
            # tables) means the elements ARE pointers. Diverging undersizes
            # the allocation and the image silently overruns the next global.
            var ac = kv
            ac.into:
              let arrT = resolveType(g.prog, ac)
              var esz: int
              if arrT.kind == TagLit and arrT.typeKind in {PtrT, AptrT}:
                esz = WebPtrSize
              else:
                let elemT = innerType(g.prog, arrT)
                (esz, _) = typeSizeAlign(g.prog, elemT)
              skip ac
              var n = 0
              while ac.hasMore: (inc n; skip ac)
              result += n * esz
          while kv.hasMore: skip kv
      skip t

proc declHasInit(decl: Cursor): bool =
  ## True when a `(gvar|tvar :name PRAGMAS TYPE INIT?)` carries an initializer.
  var d = decl
  result = false
  d.into:
    inc d                                      # name
    skip d                                     # pragmas
    skip d                                     # type
    result = d.hasMore and d.kind != DotToken
    while d.hasMore: skip d

proc globalAddrOf(g: var WebGen; name: string): uint32 =
  ## The linear-memory address of a gvar/const — foreign ones included, the
  ## lazy loader resolves their decls and the layout here is whole-program.
  ## The address is keyed by `gvarRefName`: a C-linkage PAIR (the defining
  ## `exportc` gvar and a body module's `importc` reference) shares one C
  ## symbol, so it must share one slot — two names, two addresses, is the
  ## silent-zero miscompile arkham's `gvarRefName` exists to prevent.
  ## Zero-initialized globals reserve space only; static initializers become
  ## image segments in `serializeStatics`.
  let canon = lengSym(g, gvarRefName(g.prog, name))
  if g.globalAddr.hasKey(canon): return g.globalAddr[canon]
  let si = lookupSym(typeCtx(g), name)
  if si.cat notin {scGlobal, scTvar}:          # tvar: single-threaded target → a global
    err g, "not a global: " & name
  var d = si.decl
  var typ: Cursor
  var initv: Cursor
  var hasInit = false
  d.into:
    inc d                                      # name
    skip d                                     # pragmas
    typ = d
    skip d
    if d.hasMore and d.kind != DotToken:
      initv = d
      hasInit = true
    while d.hasMore: skip d
  var (sz, al) = typeSizeAlign(g.prog, typ)
  if hasInit:
    sz += flexPayloadLen(g, initv)
  result = allocStatic(g, sz, al, tag = poolSym(g.lengPool, canon))
  g.globalAddr[canon] = result
  # The decl to serialize: prefer one that carries an initializer, so an
  # `importc` reference seen first cannot hide the defining module's static.
  if not g.canonDecl.hasKey(canon) or
      (hasInit and not declHasInit(g.canonDecl[canon])):
    g.canonDecl[canon] = si.decl
  if si.cat == scGlobal and not g.globals.hasKey(name):
    g.globals[name] = si.decl                  # cache foreign decls for typenav
  elif si.cat == scTvar and not g.tvars.hasKey(name):
    g.tvars[name] = si.decl

proc strLitAddr(g: var WebGen; s: string): uint32 =
  if g.rodataAddr.hasKey(s): return g.rodataAddr[s]
  result = allocStatic(g, s.len + 1, 1, tag = "strlit")  # NUL-terminated, like the C backend
  g.rodataAddr[s] = result
  g.dataSegs.add (result, s & '\0')

proc tableSlotOf(g: var WebGen; sym: SymId): uint32 =
  ## A proc as a VALUE is an index into the function table — the twin of
  ## wasm's funcref table, with 0 reserved for nil.
  if g.tableSlot.hasKey(sym): return g.tableSlot[sym]
  result = g.nextTableSlot
  inc g.nextTableSlot
  g.tableSlot[sym] = result
  while g.tableEntries.len <= int(result): g.tableEntries.add SymId(0)
  g.tableEntries[int(result)] = sym         # bound to its IR name at the end

proc procDeclOf(g: var WebGen; nm: SymId; found: var bool): Cursor
proc ensureProc(g: var WebGen; sym: SymId; decl: Cursor)

proc procValue(g: var WebGen; sym: SymId): uint32 =
  ## A proc as a VALUE: its function-table slot, AND a reachability edge —
  ## ithaqua's `tableSlotOf` resolves through `refProc`, which declares the
  ## body. A slot for a proc nobody lowered would bind the "unbound extern"
  ## stub: right for a bodyless import, wrong for a body that was forgotten.
  result = tableSlotOf(g, sym)
  var found = false
  let decl = procDeclOf(g, sym, found)
  if found: ensureProc(g, sym, decl)

# ── object offsets ───────────────────────────────────────────────────────────

proc fieldOffsetIn(g: var WebGen; objType: Cursor; field: string;
                   found: var bool): int =
  ## Byte offset of `field` inside the RESOLVED object type `objType` (own
  ## fields only; the caller walks inheritance). Mirrors `objSizeAlign`.
  var oc = objType
  var off = 0
  found = false
  oc.into:
    if oc.kind == Symbol:                      # an inherited base occupies the front
      let (bsz, _) = typeSizeAlign(g.prog, oc)
      off = bsz
    skip oc
    while oc.hasMore:
      if oc.kind == TagLit and oc.typeKind == UnionT:
        # A variant payload (hexer lowers case objects to a union of
        # anonymous objects): every branch OVERLAYS at the union's offset.
        let (usz, ual) = typeSizeAlign(g.prog, oc)
        off = align(off, int(ual))
        var un = oc
        un.into:
          while un.hasMore:
            if not found:
              # Object-variant branches are `(of RANGES BODY)` (the body may be
              # `.` when the branch declares no fields); `{.union.}` children are
              # bare objects. `unionBranchBody` normalizes both.
              var bodyc = unionBranchBody(un)
              if bodyc.kind != DotToken:
                var inner = false
                let innerOff = fieldOffsetIn(g, bodyc, field, inner)
                if inner:
                  found = true
                  result = off + innerOff
            skip un
        if not found:
          off += int(usz)
        skip oc
        continue
      oc.into:                                 # (fld :name pragmas type)
        let fn = symName(oc); inc oc
        skip oc                                # pragmas
        let (fsz, fal) = typeSizeAlign(g.prog, oc)
        skip oc
        off = align(off, fal)
        if fn == field:
          found = true
          result = off
          while oc.hasMore: skip oc
        off += fsz
      if found:
        while oc.hasMore: skip oc              # keep the `into` balanced
        return

proc dotOffset(g: var WebGen; baseType: Cursor; field: string; depth: int): int =
  ## Offset of `field` accessed at inheritance `depth` (0 = this object; the
  ## base subobject always sits at 0, so depth picks WHICH body declares it).
  var t = resolveType(g.prog, baseType)
  var lvl = depth
  while true:
    if t.kind == TagLit and t.typeKind == UnionT:
      return 0                                 # plain C union: members overlay
    if t.kind != TagLit or t.typeKind != ObjectT:
      err g, "dot into a non-object type"
    var oc = t
    var base: Cursor
    var hasBase = false
    oc.into:
      base = oc
      hasBase = oc.kind != DotToken
      skip oc
      while oc.hasMore: skip oc
    if lvl > 0:
      if not hasBase: err g, "dot inheritance depth exceeds bases"
      t = resolveType(g.prog, base)
      dec lvl
    else:
      var found = false
      let off = fieldOffsetIn(g, t, field, found)
      if found: return off
      if not hasBase: err g, "field not found: " & field
      t = resolveType(g.prog, base)

# ── constant initializers ────────────────────────────────────────────────────

proc putLE(bytes: var string; off: int; v: uint64; width: int) =
  ## Write `width` little-endian bytes of `v` at `off`, zero-extending.
  while bytes.len < off + width: bytes.add '\0'
  var x = v
  for i in 0 ..< width:
    bytes[off + i] = char(x and 0xFF)
    x = x shr 8

proc isAggregateGlobal(g: var WebGen; nm: string): bool =
  ## True when `nm` names a gvar/tvar/const whose DECLARED type is an
  ## aggregate (skMem) — the case where a C cast of the bare symbol means
  ## array decay to its address rather than a value read.
  let si = lookupSym(typeCtx(g), nm)
  if si.cat notin {scGlobal, scTvar}: return false
  var d = si.decl
  result = false
  d.into:
    inc d                                      # name
    skip d                                     # pragmas
    result = scalOf(g, d).kind == skMem
    while d.hasMore: skip d

proc constScalarBits(g: var WebGen; v: Cursor; ok: var bool): uint64 =
  ## The bit pattern of a compile-time scalar. Addresses resolve to absolute
  ## numbers because the generator owns the layout — this is where a fixup lands.
  ok = true
  case v.kind
  of IntLit: result = cast[uint64](intVal(v))
  of UIntLit: result = uintVal(v)
  of CharLit: result = uint64(ord(charLit(v)))
  of FloatLit: result = cast[uint64](floatVal(v))
  of StrLit: result = uint64(strLitAddr(g, strVal(v)))
  of Symbol:
    let nm = symName(v)
    let si = lookupSym(typeCtx(g), nm)
    case si.cat
    of scProc: result = uint64(procValue(g, symId(v)))
    of scGlobal, scTvar, scNone:
      ok = false                               # a VALUE copy is a runtime init
      result = 0
  of TagLit:
    case v.exprKind
    of TrueC: result = 1
    of FalseC, NilC: result = 0
    of SufC, ParC:
      var t = v
      inc t
      result = constScalarBits(g, t, ok)
    of ConvC, CastC:
      var t = v
      t.into:
        let floatTarget = t.kind == TagLit and t.typeKind == FT
        # A pointer TARGET makes the operand's ADDRESS the value: `(cast (ptr T)
        # sym)` is what nifler emits for a reference to a const scalar, where
        # array decay does it implicitly for an aggregate.
        let ptrTarget = t.kind != DotToken and isPtrType(g, t)
        skip t                                 # the conv target type
        if floatTarget:
          # A float TARGET: still compile-time when the operand is a literal —
          # only the representation changes. The bits are the f64 form; the image
          # writer narrows them for an `f 32` global.
          case t.kind
          of FloatLit: result = cast[uint64](floatVal(t))
          of IntLit: result = cast[uint64](float64(intVal(t)))
          of UIntLit: result = cast[uint64](float64(uintVal(t)))
          of CharLit: result = cast[uint64](float64(ord(charLit(t))))
          else:
            ok = false                         # a runtime value has no bits here
            result = 0
        elif t.kind == Symbol and lookupSym(typeCtx(g), symName(t)).cat == scProc:
          # A PROC's address as a static value — an RTTI method-table entry, a
          # function pointer in a const — is its function-table slot, not a
          # memory address. ithaqua stores the funcref slot the same way.
          result = uint64(procValue(g, symId(t)))
        elif t.kind == Symbol and (ptrTarget or isAggregateGlobal(g, symName(t))):
          # The ADDRESS of a global is a layout-time constant here, since
          # the generator owns the layout. A conv of a scalar global to a NON-pointer
          # type stays a runtime value copy.
          result = uint64(globalAddrOf(g, symName(t)))
        else:
          result = constScalarBits(g, t, ok)
        while t.hasMore: skip t
    of AddrC, HaddrC:
      # The global's address: assigning it here is what makes the initializer's
      # dependency part of the layout.
      var t = v
      inc t
      if t.kind == Symbol:
        result = uint64(globalAddrOf(g, symName(t)))
      else:
        ok = false
    of NegC:
      var t = v
      t.into:
        let ty = t                             # the type child decides the kind
        skip t                                 #   of negation
        var innerOk = true
        let inner = constScalarBits(g, t, innerOk)
        ok = innerOk
        let sc = scalOf(g, ty)
        result = if sc.kind in {skF32, skF64}:
          # IEEE negation flips the sign bit; subtracting the bit pattern from
          # zero produces a different number entirely. Floats are held as the
          # f64 pattern here — serializeConstInto narrows f32 at the write.
          inner xor (1'u64 shl 63)
        else:
          cast[uint64](0'i64 - cast[int64](inner))
        while t.hasMore: skip t
    else:
      ok = false
  else:
    ok = false

proc serializeConstInto(g: var WebGen; bytes: var string; base: int;
                        typ, v: Cursor) =
  ## Serialize a compile-time aggregate/scalar initializer at `base` in
  ## `bytes`; offsets mirror the runtime layout queries, so a constant and a
  ## load of the same field agree by construction.
  let rt = resolveType(g.prog, typ)
  if v.kind == TagLit and v.exprKind == OconstrC:
    var t = v
    t.into:
      let objT = resolveType(g.prog, t)
      skip t
      while t.hasMore:
        if t.substructureKind != KvU: err g, "malformed const oconstr"
        var kv = t
        kv.into:
          let field = symName(kv); inc kv
          let value = kv
          skip kv
          var fdepth = 0
          if kv.hasMore and kv.kind == IntLit:
            fdepth = int(intVal(kv))
          while kv.hasMore: skip kv
          let off = dotOffset(g, objT, field, fdepth)
          let ft = fieldType(g.prog, objT, field)
          let ftr = resolveType(g.prog, ft)
          if ftr.kind == TagLit and ftr.typeKind == FlexarrayT:
            if value.kind == StrLit:
              let s = strVal(value)
              while bytes.len < base + off: bytes.add '\0'
              for ch in s: bytes.add ch
              bytes.add '\0'
            elif value.kind == TagLit and value.exprKind == AconstrC:
              serializeConstInto(g, bytes, base + off, ftr, value)
            else:
              err g, "unsupported flexarray const payload"
          else:
            serializeConstInto(g, bytes, base + off, ft, value)
        skip t
  elif v.kind == TagLit and v.exprKind == AconstrC:
    var t = v
    t.into:
      let arrT = resolveType(g.prog, t)
      var elemT: Cursor
      var esz: int
      if arrT.kind == TagLit and arrT.typeKind in {PtrT, AptrT}:
        elemT = arrT                           # a method table: the slots ARE pointers
        esz = WebPtrSize
      else:
        elemT = innerType(g.prog, arrT)
        (esz, _) = typeSizeAlign(g.prog, elemT)
      skip t
      var idx = 0
      while t.hasMore:
        serializeConstInto(g, bytes, base + idx * esz, elemT, t)
        skip t
        inc idx
  elif v.kind == TagLit and v.exprKind == NilC:
    putLE(bytes, base, 0, WebPtrSize)
  elif v.kind == Symbol and isPtrType(g, rt) and
      lookupSym(typeCtx(g), symName(v)).cat in {scGlobal, scTvar}:
    # Object-file semantics: a symbol written into POINTER-typed data denotes
    # its ADDRESS — what arkham's data section relocates to, and what makes
    # `(gvar p (ptr T) g)` point at `g`. A symbol in non-pointer data is a
    # VALUE copy, a runtime init the `ini` chain owns.
    putLE(bytes, base, uint64(globalAddrOf(g, symName(v))), WebPtrSize)
  else:
    let sc = scalOf(g, rt)
    if sc.kind == skMem:
      err g, "unsupported aggregate const initializer form"
    var ok = true
    var bits = constScalarBits(g, v, ok)
    if not ok: err g, "const initializer is not compile-time evaluable"
    if sc.kind == skF32:
      bits = uint64(cast[uint32](float32(cast[float64](bits))))
    putLE(bytes, base, bits, max(sc.bits div 8, 1))

proc staticInit(g: var WebGen; decl: Cursor; typ, initv: var Cursor;
                hasInit: var bool): bool =
  ## The initializer of a global DECL, but only when it is genuinely STATIC.
  ## Zero inits need no segment (the buffer starts zeroed) and runtime inits
  ## are the `ini` chain's job — skipping them here must not be an error.
  hasInit = false
  result = false
  var d = decl
  d.into:
    inc d                                      # name
    skip d                                     # pragmas
    typ = d
    skip d
    if d.hasMore and d.kind != DotToken:
      initv = d
      hasInit = true
    while d.hasMore: skip d
  if not hasInit: return
  if initv.kind == TagLit and initv.exprKind in {FalseC, NilC}: return
  if initv.kind == Symbol:
    let ic = lookupSym(typeCtx(g), symName(initv)).cat
    if ic == scProc: discard                   # the function-table slot
    elif ic in {scGlobal, scTvar} and isPtrType(g, typ): discard
                                             # a POINTER-typed symbol init is an
                                             # address fixup, static by nature
    else: return                               # a value copy from another global
  if initv.kind == TagLit and initv.exprKind in {ConvC, CastC}:
    # Static only when the operand is itself compile-time; a conv of a
    # global's value is the ini chain's job.
    var t = initv
    var staticInner = false
    t.into:
      let ptrTarget = t.kind != DotToken and isPtrType(g, t)
      skip t                                   # the conv target type
      staticInner = t.kind in {IntLit, UIntLit, CharLit, FloatLit, StrLit} or
        (t.kind == TagLit and t.exprKind in {TrueC, FalseC, SufC, NegC}) or
        # a cast to a pointer holds an ADDRESS, which the layout already knows;
        # a cast of a PROC holds its function-table slot, also a static value
        (ptrTarget and t.kind == Symbol and
         lookupSym(typeCtx(g), symName(t)).cat in {scGlobal, scTvar}) or
        (t.kind == Symbol and lookupSym(typeCtx(g), symName(t)).cat == scProc)
      while t.hasMore: skip t
    result = staticInner
  elif initv.kind == TagLit and
      initv.exprKind notin {OconstrC, AconstrC, TrueC, SufC, ParC, AddrC, HaddrC, NegC}:
    result = false                             # runtime-computed init
  else:
    result = true

proc serializeStatics(g: var WebGen) =
  ## Turn every addressed global's static initializer into image segments.
  ## Runs to a fixpoint: serializing one global can name another (`(addr g)`,
  ## a method table), which discovers a new address. `staticsDone` persists
  ## across calls — codegen addresses foreign globals on demand, and
  ## `generateJs` drains them after the last body is lowered.
  while true:
    var round: seq[(string, SymId)] = @[]
    for n in g.globalAddr.keys:
      if not g.staticsDone.containsOrIncl(n):
        round.add (poolSym(g.lengPool, n), n)
    # by SPELLING: a deterministic image, and pool ids are allocation order,
    # which is not stable across runs
    sort(round, proc (a, b: (string, SymId)): int = cmp(a[0], b[0]))
    if round.len == 0: break
    for (_, n) in round:
      var typ, initv: Cursor
      var hasInit = false
      if not staticInit(g, g.canonDecl[n], typ, initv, hasInit): continue
      var bytes = ""
      serializeConstInto(g, bytes, 0, typ, initv)
      if bytes.len > 0:
        g.dataSegs.add (g.globalAddr[n], bytes)

proc layoutProgram*(g: var WebGen) =
  ## Assign every global and thread-local an address and serialize the statics
  ## known up front; what codegen discovers later is drained before emission.
  var names: seq[string] = @[]
  for n in g.globals.keys: names.add n
  for n in g.tvars.keys: names.add n
  sort names                                   # a deterministic layout, not Table order
  for n in names: discard globalAddrOf(g, n)
  serializeStatics(g)

proc checkSegments(g: var WebGen) =
  ## No segment may write past the allocation it was given: an undersized
  ## global silently corrupts its neighbour, which surfaces far away.
  for (at, s) in g.dataSegs:
    var owner = -1
    var ownerStart = 0'u32
    for i, (a, sz, _) in g.allocLog:
      if a <= at and at < a + sz:
        # the innermost allocation containing it, when one is nested in another
        if owner < 0 or a >= ownerStart:
          owner = i
          ownerStart = a
    if owner < 0:
      err g, "data segment at " & $at & " lies outside every allocation"
    let (a, sz, tag) = g.allocLog[owner]
    if uint64(at) + uint64(s.len) > uint64(a) + uint64(sz):
      err g, "data segment at " & $at & " (" & $s.len &
        " bytes) overruns `" & tag & "` (" & $sz & " bytes at " & $a & ")"

const
  ImpWrite* = "nim_write"   ## the host floor: every program may write and exit
  ImpExit* = "nim_exit"
  GlobErrv* = "errv"        ## the flag model's two registers: scalar globals
  GlobOvf* = "ovf"          ## that no address ever reaches
  MemcmpFunc = "memcmp_synth" ## the synthetic byte compare (no `n_` prefix:
                              ## no Nim symbol can land on it)

proc createWebGen*(buf: var TokenBuf; inputPath: string; tags: TagPool;
                   target = wtJs; hostImports = false): WebGen =
  setTargetWord Wasm32               # the linear-memory model: 4-byte pointers
  result.tags = tags
  result.target = target
  result.hostImports = hostImports
  result.memTop = NullGuard
  result.nextTableSlot = 1           # slot 0 stays the null function pointer
  result.usedNames = initHashSet[string]()
  let webTags = createWebTagPool()
  result.lengPool = buf.pool          # the pool every Leng `SymId` below belongs to
  result.top = createTokenBuf(sharedTags = webTags)
  result.irPool = result.top.pool
  # the body buffer shares the program's pools: a finished body is appended
  # to `top` as one bulk copy
  result.outp = createTokenBuf(sharedPool = result.top.pool, sharedTags = webTags)
  result.imports = @[
    WebImport(name: ImpWrite, params: @[wI32, wU32, wI32], hasRet: true, ret: wI32),
    WebImport(name: ImpExit, params: @[wI32])]
  result.impWrite = result.irPool.syms.getOrIncl ImpWrite
  result.impExit = result.irPool.syms.getOrIncl ImpExit
  result.globErrv = result.irPool.syms.getOrIncl GlobErrv
  result.globOvf = result.irPool.syms.getOrIncl GlobOvf
  result.memcmpFn = result.irPool.syms.getOrIncl MemcmpFunc
  for n in [ImpWrite, ImpExit, GlobErrv, GlobOvf, MemcmpFunc]:
    result.usedNames.incl n           # the runtime floor owns these spellings
  result.importOf = initTable[string, SymId]()
  result.callTarget = initTable[string, CallTarget]()
  result.globals = initTable[string, Cursor]()
  result.tvars = initTable[string, Cursor]()
  result.globalAddr = initTable[SymId, uint32]()
  result.canonDecl = initTable[SymId, Cursor]()
  result.staticsDone = initHashSet[SymId]()
  result.rodataAddr = initTable[string, uint32]()
  result.tableSlot = initTable[SymId, uint32]()
  result.irNameOf = initTable[SymId, SymId]()
  result.emitted = initHashSet[SymId]()
  result.p.symType = initTable[string, Cursor]()
  result.p.locals = initTable[string, LocalSlot]()
  result.prog = collect(buf, inputPath, tags)
  result.callTarget = result.prog.callTarget
  for name, decl in result.prog.globals:
    result.globals[name] = decl
  for name, decl in result.prog.tvars:
    result.tvars[name] = decl

# ── code generation ──────────────────────────────────────────────────────────
## Leng → web IR. A scalar travels as a value of its width; a pointer is a
## 32-bit offset into linear memory, and an aggregate lives in linear memory.
## Anything not yet understood is REFUSED by name — a half-lowered program is
## worse than no program.

proc lengType(g: var WebGen; c: Cursor): Cursor = getType(typeCtx(g), c)

proc exprScal(g: var WebGen; c: Cursor): Scal = scalOf(g, lengType(g, c))

proc widthOf(sc: Scal): WidthCode =
  result = case sc.kind
    of skI32:
      case sc.bits
      of 8: (if sc.signed: wI8 else: wU8)
      of 16: (if sc.signed: wI16 else: wU16)
      else: (if sc.signed: wI32 else: wU32)
    of skI64: (if sc.signed: wI64 else: wU64)
    of skF32: wF32
    of skF64: wF64
    of skMem: wU32               # a pointer is an unsigned offset into the buffer

proc widthOf(g: var WebGen; t: Cursor): WidthCode = widthOf(scalOf(g, t))

proc widthBits(w: WidthCode): int =
  case w
  of wI8, wU8: 8
  of wI16, wU16: 16
  of wI32, wU32, wF32: 32
  of wI64, wU64, wF64: 64

proc unsignedOf(w: WidthCode): WidthCode =
  case w
  of wI8: wU8
  of wI16: wU16
  of wI32: wU32
  else: w

proc sufWidth(g: var WebGen; s: string): WidthCode =
  ## The width a NIF numeric suffix names. Nifler marks an EXPLICITLY typed
  ## literal (`5'u32`) with a leading `+`, which says nothing about the width.
  ## These are the only widths there are; an unknown suffix is a dialect
  ## change, not something to guess at.
  let s = if s.len > 0 and s[0] == '+': s[1 .. ^1] else: s
  case s
  of "i8": wI8
  of "u8": wU8
  of "i16": wI16
  of "u16": wU16
  of "i32": wI32
  of "u32": wU32
  of "i64": wI64
  of "u64": wU64
  of "f32": wF32
  of "f64": wF64
  else: err g, "unknown numeric suffix: " & s

proc litWidth(g: var WebGen; c: Cursor): WidthCode =
  ## The width of a LITERAL. A bare literal's type is the program's natural int
  ## type — `i32` under Wasm32 — so trusting it would truncate
  ## `(conv (f 64) 9223372036854775808u)` to zero. A literal that does not fit
  ## its natural width IS a 64-bit one; a `suf` node states its width and is
  ## authoritative.
  if c.kind == TagLit and c.exprKind == SufC:
    result = widthOf(exprScal(g, c))
    var t = c
    t.into:
      skip t                                   # the value
      result = sufWidth(g, strVal(t))
      while t.hasMore: skip t
    return
  let w = widthOf(exprScal(g, c))
  if widthBits(w) >= 64: return w
  case c.kind
  of IntLit:
    let v = intVal(c)
    if v > 0xFFFFFFFF'i64 or v < -0x8000_0000'i64: wI64 else: w
  of UIntLit:
    if uintVal(c) > 0xFFFF_FFFF'u64: wU64 else: w
  else:
    w

proc freshIrName(g: var WebGen; base: string): SymId =
  ## A name in the IR pool that nothing else was given. The spelling is what
  ## can collide — two Nim symbols mangling onto one identifier would be silent
  ## wrong code — so the counter is driven by `usedNames`, and the result is
  ## interned ONCE: every later use of it is a pool id, not a string.
  var cand = base
  var n = 0
  while g.usedNames.containsOrIncl(cand):
    inc n
    cand = base & "_" & $n
  result = g.irPool.syms.getOrIncl(cand)

proc irName(g: var WebGen; sym: SymId): SymId =
  ## The IR name of a Leng symbol — also its JavaScript identifier, so it must
  ## be one: NIF names carry dots and module suffixes, which are not identifier
  ## characters in JS. The mapping is memoized, so a symbol and every later use
  ## of it get the same name. The `n_` prefix keeps every generated name clear
  ## of the runtime floor (`nim_write`, `errv`, …), of the JS preamble and of
  ## JS reserved words.
  if g.irNameOf.hasKey(sym): return g.irNameOf[sym]
  var base = "n_"
  for ch in poolSym(g.lengPool, sym):
    base.add (if ch in {'a'..'z', 'A'..'Z', '0'..'9', '_'}: ch else: '_')
  result = freshIrName(g, base)
  g.irNameOf[sym] = result

proc irName(g: var WebGen; sym: string): SymId {.inline.} =
  irName(g, lengSym(g, sym))

proc tmpName(g: var WebGen): SymId =
  ## The `n`-th generated name of the proc being lowered, reserved through the
  ## same set so a temporary can never land on a user name. The names are
  ## shared across procs — a local belongs to its function, and one spelling
  ## per index keeps the emitted JavaScript that much smaller.
  inc g.p.tmp
  while g.tmpNames.len < g.p.tmp:
    g.tmpNames.add freshIrName(g, "n_tmp_" & $(g.tmpNames.len + 1))
  g.tmpNames[g.p.tmp - 1]

proc declType(g: var WebGen; nm: string): Cursor =
  ## The declared type of a global/tvar, as a cursor into its decl.
  let si = lookupSym(typeCtx(g), nm)
  if si.cat notin {scGlobal, scTvar}: err g, "not a global: " & nm
  var d = si.decl
  d.into:
    inc d                                      # name
    skip d                                     # pragmas
    result = d
    while d.hasMore: skip d

proc genExpr(g: var WebGen; c: Cursor)
proc genAddr(g: var WebGen; c: Cursor)
proc procResultType(decl: Cursor): Cursor
proc procBody(decl: Cursor): Cursor
proc hasBody(decl: Cursor): bool

# ── scalar, pointer, aggregate ───────────────────────────────────────────────
# What a type IS decides how its value travels. A scalar is a function local
# or a frame slot; a pointer is a 32-bit offset into linear memory and can be
# dereferenced; an aggregate is a LOCATION whose "value" is its address,
# exactly as in C. `scalOf` calls pointers AND aggregates `skMem`, so the two are
# told apart by the Leng type tag, never by the slot class.

# ── frame addressing ─────────────────────────────────────────────────────────

proc slotAddr(g: var WebGen; off: int) =
  ## `fp + off`: the frame base plus a byte offset.
  if g.p.fp == SymId(0): err g, "internal: frame slot in a frameless proc"
  g.outp.openTree Add
  g.outp.width wU32
  g.outp.symUse g.p.fp
  g.outp.numLit int64(off)
  g.outp.closeTag

proc takeTemp(g: var WebGen; size: int; what: string = ""): int =
  ## The next planned temporary. `planFrame` walked the same tree in the same
  ## preorder and reserved an offset for every node that must be materialized;
  ## consuming that plan here is what keeps layout and codegen from disagreeing
  ## about where a temporary lives. A mismatch means the two walks diverged —
  ## an internal error, reported as a refusal rather than emitting a program
  ## that reads the wrong slot.
  if g.p.tmpAt >= g.p.tmpPlan.len:
    err g, "internal: unplanned temporary of " & $size & " bytes in `" &
          poolSym(g.irPool, g.p.irName) & "`"
  if g.p.tmpPlan[g.p.tmpAt].size != size:
    # A short slice of the plan around the divergence names the frame offset
    # that broke, which is far quicker to trace than the raw index.
    var dump = ""
    for q in max(0, g.p.tmpAt - 6) ..< min(g.p.tmpPlan.len, g.p.tmpAt + 3):
      dump.add ' ' & $q & ':' & $g.p.tmpPlan[q].size
    err g, "internal: temporary plan mismatch in `" & poolSym(g.irPool, g.p.irName) & "` [" & what &
           "] (planned " & $g.p.tmpPlan[g.p.tmpAt].size & ", asked " & $size & ")" & dump
  result = g.p.tmpPlan[g.p.tmpAt].off
  inc g.p.tmpAt

proc genSymAddr(g: var WebGen; c: Cursor) =
  ## The address a symbol denotes: a frame slot, the address an aggregate
  ## parameter arrived as, or a global's static address.
  let nm = symName(c)
  if g.p.locals.hasKey(nm):
    let s = g.p.locals[nm]
    case s.kind
    of lkReg: err g, "the register local `" & nm & "` has no address"
    of lkSlot: slotAddr(g, s.off)
    of lkPtr: g.outp.symUse irName(g, nm)
  else:
    let si = lookupSym(typeCtx(g), nm)
    case si.cat
    of scGlobal, scTvar:
      # A foreign global resolves through the lazy loader and is laid out HERE:
      # the layout is whole-program, so one address per C symbol, no relocation.
      g.outp.numLit int64(globalAddrOf(g, nm))
    else: err g, "not addressable: " & nm

proc genBaseAddr(g: var WebGen; c: Cursor) =
  ## The address a `dot`/`at`/`pat` walks from: a pointer's VALUE is the base,
  ## an aggregate or a local is its location.
  let t = lengType(g, c)
  if isPtrType(g, t): genExpr(g, c) else: genAddr(g, c)

proc scaledIndex(g: var WebGen; idx: Cursor; factor: int) =
  ## `index * factor` as a 32-bit offset: an address is always 32 bits in this
  ## value model, whatever the index's own width.
  let iw = widthOf(exprScal(g, idx))
  if factor == 1:
    g.outp.cvtNode(iw, wU32):
      genExpr(g, idx)
  else:
    g.outp.openTree Mul
    g.outp.width wU32
    g.outp.numLit int64(factor)
    g.outp.cvtNode(iw, wU32):
      genExpr(g, idx)
    g.outp.closeTag

proc genAddr(g: var WebGen; c: Cursor) =
  ## `(addr X)` and every lvalue base: the byte address X denotes.
  case c.kind
  of Symbol: genSymAddr(g, c)
  of TagLit:
    case c.exprKind
    of DerefC:
      var t = c
      t.into:
        genExpr(g, t)                    # a pointer's value IS the address
        while t.hasMore: skip t
    of CallC, OconstrC, AconstrC:
      # A struct-returning call and a constructor in value position both
      # materialize in a planned slot and travel as that slot's address, so the
      # address of one IS its value.
      genExpr(g, c)
    of DotC:
      var t = c
      t.into:
        let base = t
        skip t                               # `(dot BASE FIELD DEPTH?)`, in that order
        let fld = symName(t)
        inc t
        var depth = 0
        if t.hasMore and t.kind == IntLit:
          depth = int(intVal(t))
          inc t
        let bt = lengType(g, base)
        let objT = if isPtrType(g, bt): elemTypeOf(g, bt) else: bt
        let off = dotOffset(g, objT, fld, depth)
        g.outp.openTree Add
        g.outp.width wU32
        genBaseAddr(g, base)
        g.outp.numLit int64(off)
        g.outp.closeTag
        while t.hasMore: skip t
    of AtC, PatC:
      var t = c
      t.into:
        let base = t
        let esz = max(byteSize(g, elemTypeOf(g, lengType(g, base))), 1)
        g.outp.openTree Add
        g.outp.width wU32
        genBaseAddr(g, base)
        skip t                           # the array / the pointer
        scaledIndex(g, t, esz)
        g.outp.closeTag
        while t.hasMore: skip t
    of ConvC, CastC, BaseobjC:
      # A reinterpretation of an object's storage — a distinct-type wrapper
      # (`(conv Wrap.0 iv.0)`), a same-size `cast`, or a view of an object as one
      # of its bases (`(baseobj Base.0 1 x)`; arkham's `layoutObjBody` puts the
      # base subobject at offset 0). None moves a byte, so the address is the
      # operand's and only the TYPE changes. A pointer TARGET is a different
      # animal: it produces a value, not a location.
      var t = c
      t.into:
        if isPtrType(g, t): err g, "cannot take the address of `" & $c.exprKind & "`"
        skip t
        if c.exprKind == BaseobjC: skip t     # the inheritance depth
        genBaseAddr(g, t)
        while t.hasMore: skip t
    else:
      err g, "cannot take the address of `" & $c.exprKind & "`"
  else:
    err g, "cannot take the address of this expression"

proc intLitAs(g: var WebGen; v: int64; unsignedSrc: bool; want: WidthCode) =
  ## An integer literal emitted straight at the width its position demands —
  ## Leng's bare literals carry no width, the CONTEXT types them — in the
  ## canonical form of that width (a u32 is non-negative, an i8 sign-extended).
  case want
  of wF32, wF64:
    g.outp.floatLit(if unsignedSrc: float64(cast[uint64](v)) else: float64(v))
  of wI64: g.outp.bigIntLit $v
  of wU64: g.outp.bigIntLit $cast[uint64](v)
  of wI32: g.outp.numLit int64(cast[int32](v))
  of wU32: g.outp.numLit int64(cast[uint32](v))
  of wI16: g.outp.numLit int64(cast[int16](v))
  of wU16: g.outp.numLit int64(cast[uint16](v))
  of wI8: g.outp.numLit int64(cast[int8](v))
  of wU8: g.outp.numLit int64(cast[uint8](v))

proc genExprCoerced(g: var WebGen; c: Cursor; want: WidthCode) =
  ## The one place the numeric worlds meet: an operand is moved to the width
  ## its position demands, and only when the widths actually differ. A bare
  ## literal is emitted at that width directly (C's implicit conversion of a
  ## constant happens at compile time).
  case c.kind
  of IntLit: intLitAs(g, intVal(c), false, want); return
  of UIntLit: intLitAs(g, cast[int64](uintVal(c)), true, want); return
  of CharLit: intLitAs(g, int64(ord(charLit(c))), true, want); return
  of FloatLit:
    if want.isFloat:
      g.outp.floatLit floatVal(c)
      return
  of TagLit:
    case c.exprKind
    of TrueC, FalseC, NilC:
      intLitAs(g, (if c.exprKind == TrueC: 1 else: 0), false, want)
      return
    of ParC:
      var t = c
      t.into:
        genExprCoerced(g, t, want)
        while t.hasMore: skip t
      return
    else: discard
  else: discard
  let have = litWidth(g, c)
  if have == want:
    genExpr(g, c)
  else:
    g.outp.cvtNode(have, want):
      genExpr(g, c)

proc genSymValue(g: var WebGen; c: Cursor) =
  ## The value a symbol holds. An aggregate's value IS its address; anything
  ## else is loaded from where it lives — a function local, a frame slot, a global's
  ## static address.
  let nm = symName(c)
  if g.p.locals.hasKey(nm):
    let s = g.p.locals[nm]
    let ty = g.p.symType[nm]
    if isAggType(g, ty) or s.kind == lkPtr:
      genSymAddr(g, c)                    # a location travels as its address
    elif s.kind == lkReg:
      g.outp.symUse irName(g, nm)
    else:
      g.outp.tree HLoad:
        g.outp.width widthOf(scalOf(g, ty))
        slotAddr(g, s.off)
  else:
    let si = lookupSym(typeCtx(g), nm)
    case si.cat
    of scProc: g.outp.numLit int64(procValue(g, symId(c)))  # a proc as a value
    of scGlobal, scTvar:
      let ty = declType(g, nm)
      if isAggType(g, ty):
        g.outp.numLit int64(globalAddrOf(g, nm))         # the global's address
      else:
        g.outp.tree HLoad:
          g.outp.width widthOf(scalOf(g, ty))
          g.outp.numLit int64(globalAddrOf(g, nm))
    of scNone: err g, "unknown symbol: " & nm

# ── constructors: materializing an aggregate value ───────────────────────────

proc constrSize(g: var WebGen; c: Cursor): int =
  ## The bytes a constructor occupies. The node names its own type, so the size
  ## never depends on what typenav makes of the enclosing expression.
  var t = c
  t.into:
    result = byteSize(g, t)
    while t.hasMore: skip t
  if result <= 0: err g, "constructor of unknown size"

proc copyToSlot(g: var WebGen; dstOff: int; src: Cursor; size: int) =
  ## `memcopy(fp+dstOff, <src's address>, size)` — an EXPRESSION, so a
  ## constructor fill composes inside a `Seq`.
  g.outp.openTree MemCopy
  slotAddr(g, dstOff)
  genBaseAddr(g, src)
  g.outp.numLit int64(size)
  g.outp.closeTag

proc storeSlot(g: var WebGen; off: int; w: WidthCode; val: Cursor) =
  g.outp.openTree HStore
  g.outp.width w
  slotAddr(g, off)
  g.genExprCoerced(val, w)
  g.outp.closeTag

proc zeroSlot(g: var WebGen; off, size: int) =
  ## `memfill(fp+off, 0, size)`: the shadow stack is reused memory, and an
  ## uninitialized local must read as zero, as a function local does.
  g.outp.openTree MemFill
  slotAddr(g, off)
  g.outp.numLit 0
  g.outp.numLit int64(size)
  g.outp.closeTag

proc partName(c: Cursor): string =
  ## The type name an `oconstr` declares, read without entering its entries.
  var t = c
  inc t
  symName(t)

proc entryIsCtor(kv: Cursor): bool =
  ## Is the VALUE slot of a `(kv NAME VALUE DEPTH?)` entry itself a constructor?
  ## Read without entering, as `partName` does: the name is a leaf symbol, so
  ## two steps from the `kv` tag reach the value.
  var t = kv
  inc t                                    # the field name
  inc t                                    # the value
  t.kind == TagLit and t.exprKind in {OconstrC, AconstrC}

proc isInheritedPart(g: var WebGen; objTy: Cursor; part: string): bool =
  ## Is `part` one of `objTy`'s bases? Only the base chain says which nested
  ## `oconstr` is the inherited part, and guessing would write it at offset 0 of
  ## an object it does not belong to.
  var t = resolveType(g.prog, objTy)
  while t.kind == TagLit and t.typeKind == ObjectT:
    var oc = t
    var base: Cursor
    var hasBase = false
    oc.into:
      base = oc
      hasBase = oc.kind != DotToken
      while oc.hasMore: skip oc
    if not hasBase or base.kind != Symbol: break
    if symName(base) == part: return true
    t = resolveType(g.prog, base)

proc genCtorInto(g: var WebGen; destOff: int; c: Cursor) =
  ## Fill the frame slot at `destOff` from an `oconstr`/`aconstr`, emitting one
  ## `seq` expression whose value is the destination address. A nested
  ## constructor is filled in place at its field's offset, so a literal costs
  ## one materialization, not one per level.
  var t = c
  t.into:
    let ty = t
    skip t                                   # the constructed type
    let rt = resolveType(g.prog, ty)
    if rt.kind != TagLit or rt.typeKind notin {ObjectT, ArrayT, FlexarrayT}:
      err g, "constructor of a non-aggregate type"
    g.outp.openTree Seq
    var elemOff = 0
    var isFirst = true
    while t.hasMore:
      var val: Cursor
      var off = 0
      var vt: Cursor
      var header = false
      if rt.typeKind != ObjectT:
        val = t
        let et = elemTypeOf(g, ty)
        off = destOff + elemOff
        elemOff += max(byteSize(g, et), 1)
        vt = et
      elif t.kind == TagLit and t.substructureKind == KvU:
        var fld = ""
        var fdepth = 0
        var kv = t
        kv.into:
          fld = symName(kv)
          inc kv
          val = kv
          skip kv                                # `into` wants the value consumed too
          if kv.hasMore and kv.kind == IntLit:
            fdepth = int(intVal(kv))             # the field's inheritance level
          while kv.hasMore: skip kv
        # The FIELD's type, never the value's: `(kv x.0 4)` gives `4` the
        # program's natural i32, and storing a u8 field as an i32 walks over
        # its neighbours.
        vt = fieldType(g.prog, rt, fld)
        off = destOff + dotOffset(g, ty, fld, fdepth)
      elif isFirst:
        # The INHERITANCE HEADER, ahead of the named fields: either the vtable
        # pointer of a RootObj-derived object (`(addr T.vt.)`) stored in the slot
        # at offset 0 — as ithaqua stores it — or a nested `oconstr` for the base
        # subobject, which fills that same region IN PLACE.
        header = t.kind != TagLit or t.exprKind != OconstrC
        if not header and not isInheritedPart(g, ty, partName(t)):
          err g, "`oconstr` part of a type that is not a base"
        val = t
        off = destOff
      else:
        err g, "malformed `oconstr` entry"
      isFirst = false
      if header:
        storeSlot(g, off, wU32, val)
      elif val.kind == TagLit and val.exprKind in {OconstrC, AconstrC}:
        genCtorInto(g, off, val)             # nested: filled in place
      elif isAggType(g, vt):
        copyToSlot(g, off, val, byteSize(g, vt))
      elif isPtrType(g, vt) or val.kind == StrLit:
        storeSlot(g, off, wU32, val)         # a string literal is its address
      else:
        storeSlot(g, off, widthOf(scalOf(g, vt)), val)
      skip t
    slotAddr(g, destOff)                     # the sequence's value
    g.outp.closeTag

# ── frame planning ───────────────────────────────────────────────────────────

proc collectNames(c: Cursor; taken: var HashSet[string]) =
  ## Every symbol name in a subtree.
  case c.kind
  of Symbol: taken.incl symName(c)
  of TagLit:
    var t = c
    t.into:
      while t.hasMore:
        collectNames(t, taken)
        skip t
  else: discard

proc markTaken(c: Cursor; taken: var HashSet[string]) =
  ## Every name whose address is taken, at any depth. Such a local cannot live
  ## in a function local: nothing can point at one, and a Nim address is an
  ## offset into linear memory.
  if c.kind != TagLit: return
  if c.exprKind in {AddrC, HaddrC}:
    # Mark EVERY name in the operand, not just a top-level symbol: the base of
    # `(addr (baseobj …))` / `(addr (dot …))` needs a slot too. The walk
    # over-approximates on purpose — names that are not locals are ignored, and
    # the safe direction is a slot, since a missed mark means a wrong address
    # while a spurious one only costs frame space.
    var t = c
    t.into:
      collectNames(t, taken)
      while t.hasMore: skip t
    return
  var t = c
  t.into:
    while t.hasMore:
      markTaken(t, taken)
      skip t

proc ctorType(g: var WebGen; c: Cursor): Cursor =
  ## The type an `oconstr`/`aconstr` builds.
  var t = c
  t.into:
    result = t
    while t.hasMore: skip t

proc calleeProctype(g: var WebGen; target: Cursor): Cursor =
  ## The proctype of a callee expression, or a NIL cursor when there is no
  ## proctype to speak of — an unresolvable symbol, a non-function value.
  ## typenav's rule for a call's type is the callee proctype's return child;
  ## an unknown symbol would trip its `raiseAssert`, so the check that turns
  ## it into a refusal naming the symbol happens here instead.
  if target.kind == Symbol:
    let nm = symName(target)
    if not g.p.symType.hasKey(nm) and lookupSym(typeCtx(g), nm).cat == scNone:
      return Cursor()
  var pt = resolveType(g.prog, lengType(g, target))
  if pt.kind == TagLit and pt.typeKind != ProctypeT:
    var inner = pt; inc inner
    pt = resolveType(g.prog, inner)            # peel `(ptr proctype)`
  if pt.kind == TagLit and pt.typeKind == ProctypeT: result = pt

proc calleeResultType(g: var WebGen; target: Cursor): Cursor =
  ## The result type from a call TARGET cursor — the same child a call node
  ## opens with. `(onerr ACTION FN ARGS…)` reaches the call through here
  ## because its target is not the first child of the node itself.
  var pt = calleeProctype(g, target)
  if not pt.cursorIsNil:
    pt.into:                                   # (proctype NAME PARAMS RET PRAGMAS)
      skip pt; skip pt
      result = pt
      while pt.hasMore: skip pt

proc callResultType(g: var WebGen; c: Cursor): Cursor =
  ## The result type of a call node — direct or indirect — by typenav's ONE
  ## rule: the return type of the callee's proctype. `planFrame` and codegen
  ## must agree on which calls carry an sret destination, and deriving both
  ## from this one rule is what makes them agree by construction.
  var t = c
  t.into:
    result = calleeResultType(g, t)
    while t.hasMore: skip t

proc callDestSize(g: var WebGen; c: Cursor): (int, int) =
  ## What the CALLER must reserve for a call's result: (size, align) when the
  ## result is an aggregate (the struct-return slot), (0, 8) otherwise.
  result = (0, 8)
  if c.kind != TagLit or c.exprKind != CallC: return
  let rt = callResultType(g, c)
  if not rt.cursorIsNil and isAggType(g, rt): result = (byteSize(g, rt), byteAlign(g, rt))

proc aggArgFresh(t: Cursor): bool =
  ## Argument roots that ALREADY sit in fresh, node-private storage: a
  ## constructor materialized into its own temp, and a call's sret
  ## destination. Everything else must be copied before crossing the call
  ## boundary.
  t.kind == TagLit and t.exprKind in {OconstrC, AconstrC, CallC}

proc aggArgDestSize(g: var WebGen; c: Cursor): (int, int) =
  ## What the CALLER must reserve for an aggregate ARGUMENT: a fresh copy
  ## `(size, align)`, or `(0, 8)` when the argument rides through as it is —
  ## not an aggregate, already fresh, or a type that cannot be resolved. The
  ## unresolvable case must not assert here: the refusal for a bad argument
  ## comes from codegen, naming the symbol, and the plan may not outrun it.
  ## `planFrame` and `genCall` both consult THIS one predicate, which is how
  ## the reserved slot and the taken temp cannot disagree.
  result = (0, 8)
  if aggArgFresh(c): return
  if c.kind == Symbol:
    let nm = symName(c)
    if not g.p.symType.hasKey(nm) and lookupSym(typeCtx(g), nm).cat == scNone: return
  let lt = lengType(g, c)
  if not lt.cursorIsNil and isAggType(g, lt): result = (byteSize(g, lt), byteAlign(g, lt))

type
  FramePlan = object
    ## The state of the pre-order frame walk: which names must be addressable,
    ## and the next free byte offset in the frame.
    taken: HashSet[string]
    off: int

proc isHostDeclaration(decl: Cursor): bool
  ## Forward declaration; defined with `ensureProc`. `genCallFrom` needs it to
  ## refuse a bodyless extern (importc/importcpp/importjs) at the call site.
proc hasPragma(decl: Cursor; want: LengPragma): bool
  ## Forward declaration; defined with the pragma helpers. `genCallFrom` needs
  ## it to route a bodyless `importjs` proc to the splice.
proc planNode(g: var WebGen; pl: var FramePlan; c: Cursor; needsTemp: bool) =
  if c.kind != TagLit: return
  if c.stmtKind == VarS:
    var t = c
    t.into:
      let nm = symName(t); inc t
      skip t                                   # pragmas
      var typ = t
      if typ.kind == DotToken:
        # The optimizer passes synthesize `(var :t . . INIT)` with no type
        # spelled out; infer it from the initializer, as lengc does.
        var v = t
        inc v
        if v.kind == DotToken: err g, "local `" & nm & "` has no type"
        typ = lengType(g, v)
      g.p.symType[nm] = typ
      if isAggType(g, typ) or nm in pl.taken:
        let al = byteAlign(g, typ)
        pl.off = align(pl.off, al)
        g.p.locals[nm] = LocalSlot(kind: lkSlot, off: pl.off, taken: true)
        pl.off += max(byteSize(g, typ), 8)
      else:
        g.p.locals[nm] = LocalSlot(kind: lkReg)
        if nm notin g.p.regLocals: g.p.regLocals.add nm
      var init = t
      skip init                                # `inc` would ENTER the type, not pass it
      if init.kind == TagLit:
        # Mirror `genVar`: a constructor initializer is materialized into a
        # temporary only when the variable is NOT itself an aggregate (a `seq`
        # or `ptr` slot takes the literal's address, so the literal needs a
        # home); an aggregate-typed variable is filled in place and needs none.
        # Any other initializer keeps `needsTemp` so a call's sret destination
        # is reserved here, matching `copyToSlot`/`genExpr`.
        let initNeeds = if init.exprKind in {OconstrC, AconstrC}:
                          not isAggType(g, typ)
                        else:
                          true
        planNode(g, pl, init, initNeeds)
      while t.hasMore: skip t
    return
  if c.stmtKind == OnerrS:
    # `(onerr ACTION FN ARGS…)` performs a CALL, so an aggregate result needs
    # an sret destination exactly as for `(call …)` — reserved HERE, before
    # the generic walk below reserves the arguments' fresh copies, because
    # that is the order `genOnerr` takes the temps in.
    var t = c
    t.into:
      skip t                                   # the action carries no temps
      let rt = calleeResultType(g, t)
      if not rt.cursorIsNil and isAggType(g, rt):
        let sz = byteSize(g, rt)
        pl.off = align(pl.off, byteAlign(g, rt))
        g.p.tmpPlan.add TempSlot(off: pl.off, size: sz)
        pl.off += max(sz, 8)
      while t.hasMore: skip t                  # the target and args are planned
                                               # by the generic walk below
    # fall through: the generic walk plans the action and the argument copies
  var nest = needsTemp
  let isCtorNode = c.exprKind in {OconstrC, AconstrC}
  if isCtorNode and needsTemp:
    let sz = constrSize(g, c)
    let al = byteAlign(g, ctorType(g, c))
    pl.off = align(pl.off, al)
    g.p.tmpPlan.add TempSlot(off: pl.off, size: sz)
    pl.off += max(sz, 8)
    nest = false                             # nested constructors fill in place
  else:
    let (dsz, dal) = callDestSize(g, c)
    if dsz > 0:
      pl.off = align(pl.off, dal)
      g.p.tmpPlan.add TempSlot(off: pl.off, size: dsz)
      pl.off += max(dsz, 8)
  # An `importjs` splice takes bridge-typed arguments (string, cstring, handle,
  # callback) as JS values, NOT as fresh Nim copies — `genCallArgs` emits the
  # conversion instead of `genAggArg`. The plan must skip those reservations or
  # the two walks desynchronize.
  var spliceBridges: seq[JsBridgeKind]
  if c.exprKind == CallC:
    var tg = sub(c)
    if tg.kind == Symbol:
      var found = false
      let decl = procDeclOf(g, symId(tg), found)
      if found and not hasBody(decl) and hasPragma(decl, ImportjsP):
        var p = decl
        p.into:
          inc p                                # name
          p.into:                              # params
            while p.hasMore:
              var q = p
              q.into:
                inc q                          # name
                skip q                         # pragmas
                spliceBridges.add jsBridgeKind(g, q)
                while q.hasMore: skip q
              skip p
          skip p                                 # result type
          while p.hasMore: skip p                # pragmas, body
  var t = c
  t.into:
    var idx = 0                                # child 0 is the target, not an arg;
    # an `onerr` spends child 0 on the ACTION, so its args start one later:
    let argFrom = if c.stmtKind == OnerrS: 2 else: 1
    let isCallish = c.exprKind == CallC or c.stmtKind == OnerrS
    while t.hasMore:
      var childTemp = needsTemp
      if isCtorNode and t.kind == TagLit and t.substructureKind == KvU:
        # An object constructor entry `(kv NAME VALUE DEPTH?)`: `genCtorInto`
        # fills the VALUE in place at the field's offset when it is itself a
        # constructor, and materializes it otherwise (a call needs its sret, a
        # reinterpretation its own slot). Only the VALUE carries a temporary, so
        # `needsTemp` follows the value's kind, not the `kv` wrapper's.
        childTemp = not entryIsCtor(t)
      elif isCtorNode:
        # An array element, or the type child: an element that is itself a
        # constructor fills in place; a reinterpretation reaching one is read
        # as a value and needs a temporary of its own.
        childTemp = if t.kind == TagLit and t.exprKind in {OconstrC, AconstrC}: false
                    elif not nest and t.kind == TagLit and t.exprKind in {ConvC, CastC, BaseobjC}: true
                    else: needsTemp
      elif not nest and t.kind == TagLit and t.exprKind in {ConvC, CastC, BaseobjC}:
        # `genCtorInto` fills a child constructor IN PLACE, but a child that only
        # REACHES a constructor through a reinterpretation is read as a value and
        # copied — so the constructor behind it needs a temporary of its own.
        childTemp = true
      if idx >= argFrom and isCallish:
        # The aggregate argument's fresh copy is reserved HERE, before the walk
        # into the argument: `genAggArg` takes it ahead of any temporary the
        # argument's own subtree needs — the same order, or `takeTemp` refuses.
        # A splice's bridge argument rides across as a JS value instead, so
        # `genCallArgs` takes no temp for it and none is planned.
        let bi = idx - argFrom
        if not (bi < spliceBridges.len and spliceBridges[bi] != jbNone):
          let (csz, cal) = aggArgDestSize(g, t)
          if csz > 0:
            pl.off = align(pl.off, cal)
            g.p.tmpPlan.add TempSlot(off: pl.off, size: csz)
            pl.off += max(csz, 8)
      planNode(g, pl, t, childTemp)
      skip t
      inc idx

proc planFrame(g: var WebGen; body: Cursor; params: seq[(string, Cursor)];
               taken: HashSet[string]) =
  ## Give every local its frame slot (or none) and reserve a temporary for
  ## every node that must be materialized: a constructor in value position, and
  ## every call whose aggregate result needs a destination. The walk is PREORDER
  ## and reserves in exactly the order codegen asks for them — `takeTemp` checks
  ## that the two agree, so a divergence is a refusal instead of corruption.
  ##
  ## A constructor filled straight into a known destination (a `var`'s own slot,
  ## or a field inside another constructor) needs no temporary; `needsTemp`
  ## carries that context down the walk.
  var pl = FramePlan(taken: taken)
  for (pn, pt) in params:
    if isAggType(g, pt):
      # The JS argument already holds the address; no slot to point at.
      g.p.locals[pn] = LocalSlot(kind: lkPtr)
    elif pn in taken:
      g.p.locals[pn] = LocalSlot(kind: lkSlot, off: pl.off, taken: true)
      pl.off += max(byteSize(g, pt), 8)
    else:
      g.p.locals[pn] = LocalSlot(kind: lkReg)
  planNode(g, pl, body, true)
  g.p.frameSize = align(pl.off, 16)

proc jsOpOf(k: LengExpr): WebTag =
  case k
  of AddC: Add
  of SubC: Sub
  of MulC: Mul
  of DivC: Div
  of ModC: Mod
  of ShlC: Shl
  of ShrC: Shr
  of BitandC: And
  of BitorC: Or
  of BitxorC: Xor
  of EqC: Eq
  of NeqC: Neq
  of LtC: Lt
  of LeC: Le
  else: NoTag

proc genTypedBinop(g: var WebGen; c: Cursor) =
  ## `(add T a b)` — the node carries the type its operands and result share,
  ## which is exactly the WidthCode jsenc demands. Both operands are moved to
  ## it, so a mixed-width Leng operation cannot straddle Number and BigInt.
  let op = jsOpOf(c.exprKind)
  if op == NoTag: err g, "not a binary operation: " & $c.exprKind
  var t = c
  t.into:
    # arkham's shared rule, called rather than restated. `(add (ptr T) p n)`
    # does not say whether `n` counts bytes or elements, and JS is a host where
    # a wrong reading still RUNS — Number + Number gives a Number — so the web
    # back end refuses rather than inventing a semantics. `div`/`mod` are covered
    # here too, as the rule intends.
    checkArithResultType(g.prog, t, "web back end")
    let w = widthOf(g, t)
    skip t
    g.outp.openTree op
    g.outp.width w
    g.genExprCoerced(t, w)
    skip t
    g.genExprCoerced(t, w)
    g.outp.closeTag
    while t.hasMore: skip t

proc isLiteralish(c: Cursor): bool =
  c.kind in {IntLit, UIntLit, CharLit, FloatLit} or
    (c.kind == TagLit and c.exprKind == SufC)

proc genCmp(g: var WebGen; c: Cursor) =
  ## `(lt A B)` and kin. A comparison carries NO type child — the grammar gives
  ## it only its two operands — so its width comes from a NON-LITERAL operand
  ## when there is one: bare literals default to the machine word, and a
  ## suffixed literal's natural type is the bare default too, so typing the
  ## compare from it would truncate the other side (`BIGLIT <= u64var` became a
  ## signed 32-bit compare of wrapped halves). Both operands move to that width.
  let op = jsOpOf(c.exprKind)
  if op == NoTag: err g, "not a comparison: " & $c.exprKind
  var t = c
  t.into:
    let lhs = t
    var rhs = t
    skip rhs
    let w = if not isLiteralish(lhs): litWidth(g, lhs)
            elif not isLiteralish(rhs): litWidth(g, rhs)
            else: litWidth(g, lhs)
    g.outp.openTree op
    g.outp.width w
    g.genExprCoerced(t, w)
    skip t
    g.genExprCoerced(t, w)
    g.outp.closeTag
    while t.hasMore: skip t

proc sufFloatVal(g: var WebGen; lit: Cursor): float64 =
  ## The numeric value of a float-suffixed literal: nimony emits a FloatLit,
  ## an integral IntLit/UIntLit (`1.0'f32` → 1), or a `(neg LIT)` wrapper.
  case lit.kind
  of FloatLit: floatVal(lit)
  of IntLit: float64(intVal(lit))
  of UIntLit: float64(uintVal(lit))
  of TagLit:
    case lit.exprKind
    of NegC:
      var t = lit
      var v = 0.0
      t.into:
        if t.kind == TagLit and t.typeKind == FT: skip t   # a typed `neg`
        v = -sufFloatVal(g, t)
        while t.hasMore: skip t
      v
    of NanC: NaN
    of InfC: Inf
    of NeginfC: -Inf
    else: err g, "bad float literal: " & $lit.exprKind
  else: err g, "bad float literal: " & $lit.kind

proc genSufLit(g: var WebGen; c: Cursor) =
  ## `(suf LIT "i8")` — the suffix names the literal's type, and the value is
  ## brought to it: a literal wider than its suffix is truncated, as the C
  ## conversion of the constant would.
  let w = litWidth(g, c)                    # the suffix, not the natural type
  var t = c
  inc t
  if w.isFloat:
    g.outp.floatLit sufFloatVal(g, t)
  else:
    case t.kind
    of IntLit: intLitAs(g, intVal(t), false, w)
    of UIntLit: intLitAs(g, cast[int64](uintVal(t)), true, w)
    of CharLit: intLitAs(g, int64(ord(charLit(t))), true, w)
    else: err g, "unsupported suffixed literal: " & $t.kind

proc genCall(g: var WebGen; c: Cursor; wantValue: bool)
proc genInstr(g: var WebGen; c: Cursor; wantValue: bool)
proc declSignature(g: var WebGen; decl: Cursor): WebImport

proc proctypeArity(g: var WebGen; t: Cursor): int =
  ## The parameter count of the proctype a type SYMBOL names, or -1.
  result = -1
  if t.kind != Symbol: return
  var pt = resolveType(g.prog, t)
  if pt.kind != TagLit or pt.typeKind != ProctypeT: return
  var b = pt
  b.into:
    inc b                                      # name slot (`.`)
    if b.kind == TagLit and b.typeKind == ParamsT:
      result = 0
      var pc = b
      pc.into:
        while pc.hasMore: (inc result; skip pc)
    while b.hasMore: skip b

proc closureThunk(g: var WebGen; c: Cursor): bool =
  ## `(conv CLOSURE-PROCTYPE p)` of an env-less proc symbol `p`: the value is
  ## the table slot of a bridge with the closure's signature (`lowerThunk`).
  ## Detected by arity — the target proctype carries one trailing env param
  ## the proc's own declaration lacks.
  result = false
  var t = c
  t.into:
    let dstT = t
    skip t
    if t.kind == Symbol and not g.p.locals.hasKey(symName(t)):
      let opSym = symId(t)
      if lookupSym(typeCtx(g), symName(t)).cat == scProc:
        let dstArity = proctypeArity(g, dstT)
        var found = false
        let decl = procDeclOf(g, opSym, found)
        if dstArity >= 0 and found:
          let sig = declSignature(g, decl)
          var declared = sig.params.len
          var rt = procResultType(decl)
          if not rt.cursorIsNil and not isVoidType(rt) and isAggType(g, rt):
            dec declared                         # the hidden sret slot
          if dstArity == declared + 1:
            # A symbol of its own, minted in the Leng pool: no Nim name can
            # carry a second `.cthunk` suffix, so it cannot collide.
            let thunk = lengSym(g, poolSym(g.lengPool, opSym) & ".cthunk")
            if not g.tableSlot.hasKey(thunk):
              ensureProc(g, opSym, decl)
              g.thunks.add (thunk, opSym, decl)
            g.outp.numLit int64(tableSlotOf(g, thunk))
            result = true
    while t.hasMore: skip t

proc genExpr(g: var WebGen; c: Cursor) =
  case c.kind
  of Symbol: genSymValue(g, c)
  of IntLit:
    let w = litWidth(g, c)
    if w in {wI64, wU64}: g.outp.bigIntLit $intVal(c)
    else: g.outp.numLit intVal(c)
  of UIntLit:
    let w = litWidth(g, c)
    if w in {wI64, wU64}: g.outp.bigIntLit $uintVal(c)
    else: g.outp.numLit int64(uintVal(c) and 0xFFFFFFFF'u64)
  of CharLit: g.outp.numLit int64(ord(charLit(c)))
  of FloatLit: g.outp.floatLit floatVal(c)
  of StrLit: g.outp.numLit int64(strLitAddr(g, strVal(c)))   # a string is its address
  of TagLit:
    case c.exprKind
    of SufC: genSufLit(g, c)
    of ParC:
      var t = c
      t.into:
        genExpr(g, t)
        while t.hasMore: skip t
    of TrueC: g.outp.lit TrueLit
    of FalseC: g.outp.lit FalseLit
    of NilC: g.outp.numLit 0
    of SizeofC, AlignofC:
      # A compile-time constant of the natural int type (typenav's rule), and
      # the generator owns the layout that makes it known: `(sizeof T)` is just the
      # size the loader and the frame plan already agree on.
      var t = c
      t.into:
        let (sz, al) = typeSizeAlign(g.prog, t)
        g.outp.numLit int64(if c.exprKind == SizeofC: sz else: al)
        while t.hasMore: skip t
    of OvfC: g.outp.symUse GlobOvf    # the flags register: two scalar globals,
    of ErrvC: g.outp.symUse GlobErrv  # never addressable
    of NanC: g.outp.lit NanLit
    of InfC: g.outp.lit InfLit
    of NeginfC:
      g.outp.tree Neg:
        g.outp.width wF64
        g.outp.lit InfLit
    of InstrC: genInstr(g, c, wantValue = true)
    of AddC, SubC, MulC, DivC, ModC, ShlC, ShrC, BitandC, BitorC, BitxorC:
      genTypedBinop(g, c)
    of EqC, NeqC, LtC, LeC: genCmp(g, c)
    of NegC, BitnotC:
      let op = if c.exprKind == NegC: Neg else: BNot
      var t = c
      t.into:
        let w = widthOf(g, t)
        skip t
        g.outp.tree op:
          g.outp.width w
          g.genExprCoerced(t, w)
        while t.hasMore: skip t
    of NotC:
      # `(not v)` carries NO type child, unlike the arithmetic nodes.
      var t = c
      t.into:
        g.outp.tree Not:
          g.outp.width wI32
          genExpr(g, t)
        while t.hasMore: skip t
    of AndC, OrC:
      # C's `&&`/`||`: short-circuit, no type child, and no narrow-wrap — with
      # canonical 0/1 operands the result is already 0 or 1.
      let op = if c.exprKind == AndC: LAnd else: LOr
      var t = c
      t.into:
        g.outp.openTree op
        g.outp.width wI32                    # vacuous, but every op node carries one
        genExpr(g, t)
        skip t
        genExpr(g, t)
        g.outp.closeTag
        while t.hasMore: skip t
    of BaseobjC:
      # An object viewed as one of its bases: same address, different type.
      # typenav has no `baseobj` case, so the type is read from the node.
      var t = c
      t.into:
        let ty = t
        if not isAggType(g, ty): err g, "`baseobj` of a non-aggregate type"
        skip t
        skip t                                  # the inheritance depth
        genBaseAddr(g, t)
        while t.hasMore: skip t
    of ConvC, CastC:
      if isAggType(g, lengType(g, c)):
        # A record conversion between two layouts: the value, which for an
        # aggregate IS its address, does not move.
        genAddr(g, c)
        return
      if closureThunk(g, c): return
      var t = c
      t.into:
        let dst = widthOf(g, t)
        skip t
        let src = litWidth(g, t)
        # `cast` reinterprets the BIT PATTERN, so widening it zero-extends
        # whatever the source's signedness: `(cast (i 64) b)` for an i16 holding
        # -1000 is 64536 — the stored bits — where `conv` converts the VALUE and
        # sign-extends. The FROM width carries that choice to the renderer,
        # which masks narrow unsigned sources.
        let fromW = if c.exprKind == CastC and widthBits(src) < widthBits(dst):
                      unsignedOf(src)
                    else: src
        if c.exprKind == CastC and (src in {wF32, wF64}) != (dst in {wF32, wF64}):
          # `cast` between a float and an integer MOVES THE BITS — NaN's own
          # pattern, not a truncation of a value that has no integer reading.
          # Only equal sizes have bits to move; `conv` of the same pair stays
          # arithmetic.
          if widthBits(src) != widthBits(dst):
            err g, "cast between " & $src & " and " & $dst & " of different sizes"
          g.outp.reintNode(src, dst):
            genExpr(g, t)
        elif fromW == dst and src == dst:
          genExpr(g, t)
        else:
          g.outp.cvtNode(fromW, dst):
            genExpr(g, t)
        while t.hasMore: skip t
    of AddrC, HaddrC:
      # `(addr LVALUE)` — the address of anything addressable, which is exactly
      # what `genAddr` computes. A local's slot, a global's static address, the
      # pointer a `deref` walked through: all one Number.
      var t = c
      t.into:
        genAddr(g, t)
        while t.hasMore: skip t
    of DerefC, DotC, AtC, PatC:
      # An aggregate's value IS its address; a scalar is loaded through it.
      let ty = lengType(g, c)
      if isAggType(g, ty):
        genAddr(g, c)
      else:
        g.outp.tree HLoad:
          g.outp.width widthOf(scalOf(g, ty))
          genAddr(g, c)
    of OconstrC, AconstrC:
      # A constructor in value position materializes in its planned slot and
      # travels as that slot's address.
      let off = takeTemp(g, constrSize(g, c), "ctor")
      genCtorInto(g, off, c)
    of CallC: genCall(g, c, wantValue = true)
    else: err g, "unsupported expression: " & $c.exprKind
  else:
    err g, "unsupported token in an expression: " & $c.kind

# ── calls ────────────────────────────────────────────────────────────────────

proc procDeclOf(g: var WebGen; nm: SymId; found: var bool): Cursor =
  ## The `(proc …)` decl of a symbol: the main module's list, then the lazy
  ## foreign loader — ithaqua's `refProc` pattern. This is what makes the
  ## `ini` chain callable: hexer emits `main` calling `ini.0.<module>` for
  ## every import, and those procs live in the imported modules' files.
  ## Registering the typenav target on the way out is what classifies the
  ## name as a proc (and a foreign syscall as a syscall) for every later use.
  result = Cursor()
  found = false
  # `symId` compares POOL IDS: one integer against the whole proc list, where
  # `symName` would build a string per candidate on every lookup.
  for pi in g.prog.procs:
    var d = pi.decl
    inc d                                      # into: the name
    if d.kind == SymbolDef and symId(d) == nm:
      result = pi.decl
      found = true
      return
  # a bodyless `importc` of this module is an extern, not a proc to emit
  for ex in g.prog.externOrder:
    var d = ex.decl
    inc d
    if d.kind == SymbolDef and symId(d) == nm:
      result = ex.decl
      found = true
      return
  let name = poolSym(g.lengPool, nm)           # `core` asks by spelling
  if isForeignSym(g.prog, name):
    let d = lookupForeignDecl(g.prog, name, found)
    if found:
      if d.stmtKind != ProcS:
        found = false                          # a data symbol is not callable
      else:
        if not g.callTarget.hasKey(name):
          g.callTarget[name] = foreignCallTarget(g.prog, name)
        result = d

proc procResultType(decl: Cursor): Cursor =
  var d = decl
  d.into:
    inc d                                      # name
    skip d                                     # params
    result = d
    while d.hasMore: skip d

proc genSyscall(g: var WebGen; base: string; target: Cursor; t: var Cursor;
                wantValue: bool) =
  ## The runtime floor, the two host imports every program has: write goes to
  ## the host, exit leaves. Anything else is a loud runtime trap — never a
  ## silent no-op, and not a refusal that strands the whole program (the abort
  ## path, getpid/kill, lands here while the program is already dying).
  case base
  of "write":
    # The host answers in an i32; the Leng declaration may say `ssize_t`.
    let rt = calleeResultType(g, target)
    let rw = if not rt.cursorIsNil and not isVoidType(rt): widthOf(g, rt) else: wI32
    if wantValue and rw != wI32:
      g.outp.openTree Cvt
      g.outp.width wI32
      g.outp.width rw
    g.outp.openTree Call
    g.outp.symUse ImpWrite
    for i in 0 ..< 3:                          # fd, buf, len — all i32-shaped
      g.genExprCoerced(t, if i == 1: wU32 else: wI32)
      skip t
    g.outp.closeTag
    if wantValue and rw != wI32: g.outp.closeTag
    while t.hasMore: skip t
  of "exit", "_exit", "exit_group":
    # exit does not return; the trap after it says so to a host whose
    # `nim_exit` does (a browser's throws, a wasm engine's may not).
    g.outp.openTree Seq
    g.outp.openTree Call
    g.outp.symUse ImpExit
    g.genExprCoerced(t, wI32)
    g.outp.closeTag
    g.outp.lit Unreachable
    g.outp.closeTag
    while t.hasMore: skip t
  else:
    while t.hasMore: skip t
    g.outp.lit Unreachable

proc genCalleeValue(g: var WebGen; target: Cursor) =
  ## The function-table index a callee expression denotes. A proc VALUE is
  ## the slot number (`genSymValue`'s `scProc` case), so a fn-ptr local,
  ## parameter or global already holds the index — loaded, not called.
  if target.kind == Symbol:
    let nm = symName(target)
    if g.p.locals.hasKey(nm):
      let s = g.p.locals[nm]
      case s.kind
      of lkReg: g.outp.symUse irName(g, nm)
      of lkSlot:
        g.outp.tree HLoad:
          g.outp.width wU32
          slotAddr(g, s.off)
      of lkPtr: g.outp.symUse irName(g, nm)
    else:
      g.outp.tree HLoad:
        g.outp.width wU32
        g.outp.numLit int64(globalAddrOf(g, nm))    # a proc-typed gvar/tvar
  else:
    genExpr(g, target)                          # a cast or a closure-field load

proc genAggArg(g: var WebGen; t: Cursor; sz: int) =
  ## Pass an aggregate argument BY REFERENCE TO A FRESH COPY: the callee
  ## storing through its parameter must not be visible in the caller's object.
  ## `(seq (memcopy D S N) D)` makes the copy itself the argument expression.
  ## The temp is taken BEFORE the source is walked, exactly the order
  ## `planFrame` reserved it in.
  let dst = takeTemp(g, sz, "aggArg")
  g.outp.openTree Seq
  g.outp.openTree MemCopy
  slotAddr(g, dst)
  genExpr(g, t)
  g.outp.numLit int64(sz)
  g.outp.closeTag
  slotAddr(g, dst)
  g.outp.closeTag

proc paramWidth(g: var WebGen; t: Cursor): WidthCode =
  ## How a parameter of Leng type `t` travels: an aggregate as its address.
  if isAggType(g, t): wU32 else: widthOf(g, t)

proc resultWidth(g: var WebGen; t: Cursor; hasRet: var bool): WidthCode =
  ## How a result of Leng type `t` travels. An aggregate result is written
  ## through the hidden first parameter, and the function hands that address
  ## back — the value of an aggregate IS its address, so the call's value is
  ## the result, whichever target renders it.
  hasRet = not t.cursorIsNil and not isVoidType(t)
  result = if not hasRet: wI32
           elif isAggType(g, t): wU32
           else: widthOf(g, t)

proc genIndirectCall(g: var WebGen; target: Cursor; t: var Cursor) =
  ## `(call EXPR ARG*)` dispatching through a fn-ptr VALUE: the function-table
  ## slot it holds. The signature is the callee's PROCTYPE, the same one rule
  ## typenav uses to type the call — so the sret decision here and
  ## `callDestSize`'s plan cannot disagree — and it is spelled out in the
  ## `(sig …)` child: wasm's `call_indirect` checks it against the callee.
  var pt = calleeProctype(g, target)
  if pt.cursorIsNil:
    err g, (if target.kind == Symbol: "indirect call through unknown symbol " &
                                          symName(target)
            else: "indirect call through a non-proctype value")
  var retT: Cursor
  var paramsT: Cursor
  pt.into:
    skip pt                                    # the name slot
    paramsT = pt
    skip pt
    retT = pt
    while pt.hasMore: skip pt
  let aggRet = not retT.cursorIsNil and isAggType(g, retT)
  var widths: seq[WidthCode] = @[]
  if aggRet: widths.add wU32
  if paramsT.kind == TagLit:
    var pc = paramsT
    pc.into:
      while pc.hasMore:
        var q = pc
        q.into:
          inc q                                # name
          skip q                               # pragmas
          widths.add paramWidth(g, q)
          while q.hasMore: skip q
        skip pc
  # anything past the declared parameters (a varargs tail) travels at its own
  # width; the signature says so, and wasm refuses what the callee does not take
  var extra = t
  var nDeclared = widths.len - ord(aggRet)
  var k = 0
  while extra.hasMore:
    if k >= nDeclared:
      let (csz, _) = aggArgDestSize(g, extra)
      widths.add(if csz > 0: wU32 else: litWidth(g, extra))
    inc k
    skip extra
  var hasRet = false
  let rw = resultWidth(g, retT, hasRet)
  g.outp.openTree ICall
  g.outp.openTree Sig
  if hasRet: g.outp.width rw else: g.outp.addDotToken
  for w in widths: g.outp.width w
  g.outp.closeTag
  genCalleeValue(g, target)
  if aggRet: slotAddr(g, takeTemp(g, byteSize(g, retT), "ind-sret"))
  var i = ord(aggRet)
  while t.hasMore:
    let (csz, _) = aggArgDestSize(g, t)
    if csz > 0: genAggArg(g, t, csz)
    elif isAggType(g, lengType(g, t)): genExpr(g, t)
    else: g.genExprCoerced(t, widths[i])
    skip t
    inc i
  g.outp.closeTag

proc emitMemOp(g: var WebGen; t: var Cursor; widths: array[3, WidthCode]) =
  ## The three operands of a bulk memory op, each moved to its 32-bit world —
  ## a `csize_t` count arrives as an i64 on no web target.
  for w in widths:
    g.genExprCoerced(t, w)
    skip t
  while t.hasMore: skip t

proc genMemIntrin(g: var WebGen; name: string; t: var Cursor; wantValue: bool) =
  ## `memcpy/memmove(dst, src, n)`, `memset(dst, v, n)`, `memcmp(a, b, n)`.
  ## The copy is overlap-safe, so BOTH copies take it. `memcmp` has no machine
  ## form on either target: it calls the synthetic byte loop `genMemcmpFunc`
  ## emits once.
  # The CALLER owns the statement wrapper (`genStmt` wraps a call statement;
  # an expression context wants a value), so this emits a bare expression.
  case name
  of "memcpy", "memmove":
    if wantValue: err g, "memcpy result value not modelled"
    g.outp.openTree MemCopy
    emitMemOp(g, t, [wU32, wU32, wI32])
    g.outp.closeTag
  of "memset":
    if wantValue: err g, "memset result value not modelled"
    g.outp.openTree MemFill
    emitMemOp(g, t, [wU32, wI32, wI32])
    g.outp.closeTag
  of "memcmp":
    # value-returning (C's sign-of-first-difference), so unlike the copies
    # the result IS modelled; as a statement the value simply goes unused.
    g.needMemcmp = true
    g.outp.openTree Call
    g.outp.symUse g.memcmpFn
    emitMemOp(g, t, [wU32, wU32, wI32])
    g.outp.closeTag
  else:
    err g, "mem intrinsic not supported yet: " & name

proc newTemp(g: var WebGen; w: WidthCode): SymId =
  ## A generator temporary: a local of width `w`, declared with the others.
  result = tmpName(g)
  g.p.temps.add (result, w)

template setLocal(g: var WebGen; name: SymId; body: untyped) =
  ## `(assign NAME VALUE)` with VALUE built by `body`.
  g.outp.openTree Assign
  g.outp.symUse name
  body
  g.outp.closeTag

template hloadOf(g: var WebGen; w: WidthCode; name: SymId) =
  g.outp.tree HLoad:
    g.outp.width w
    g.outp.symUse name

proc genInstr(g: var WebGen; c: Cursor; wantValue: bool) =
  ## `(instr SYM args…)` — an intrinsic/instruction application (nimony
  ## #2196/#2211), typed exactly like a call. Both web targets are
  ## single-threaded, so the ATOMICS collapse to plain memory ops and the
  ## memorders are dropped. A compound row — one that reads, modifies, stores
  ## and maybe returns the old value — is a `seq` over temporaries: it keeps
  ## the operand evaluation order and drops into statement AND expression
  ## position alike. Target-pinned, flag and two-address rows have no web
  ## equivalent and stay refusals.
  var t = c
  t.into:
    let nm = symName(t)
    let it = instrTargetOf(g.prog, nm)
    skip t
    case it.op
    of AtomicLoadOp:
      let w = widthOf(scalOf(g, lengType(g, c)))
      g.outp.tree HLoad:
        g.outp.width w
        g.genExprCoerced(t, wU32)                # the pointer
        while t.hasMore: skip t                  # memorder
    of AtomicStoreOp:
      if wantValue: err g, "(instr …) atomic store has no value"
      var vc = t
      skip vc
      let w = widthOf(scalOf(g, lengType(g, vc)))
      g.outp.tree HStore:
        g.outp.width w
        g.genExprCoerced(t, wU32)                # pointer
        skip t
        g.genExprCoerced(t, w)                   # value
        while t.hasMore: skip t                  # memorder
    of AtomicAddFetchOp, AtomicSubFetchOp:
      # returns the NEW value: load, op, store.
      let w = widthOf(scalOf(g, lengType(g, c)))
      let op = if it.op == AtomicAddFetchOp: Add else: Sub
      let pv = newTemp(g, wU32)
      let rv = newTemp(g, w)
      g.outp.openTree Seq
      g.setLocal pv:
        g.genExprCoerced(t, wU32)                # pointer
        skip t
      g.setLocal rv:
        g.outp.tree op:
          g.outp.width w
          g.hloadOf(w, pv)
          g.genExprCoerced(t, w)                 # delta
          while t.hasMore: skip t                # memorder
      g.outp.tree HStore:
        g.outp.width w
        g.outp.symUse pv
        g.outp.symUse rv
      if wantValue: g.outp.symUse rv
      g.outp.closeTag
    of AtomicFetchAddOp, AtomicFetchSubOp, AtomicFetchAndOp,
       AtomicFetchOrOp, AtomicFetchXorOp:
      # returns the OLD value.
      let w = widthOf(scalOf(g, lengType(g, c)))
      let op = case it.op
               of AtomicFetchAddOp: Add
               of AtomicFetchSubOp: Sub
               of AtomicFetchAndOp: And
               of AtomicFetchOrOp: Or
               else: Xor
      let pv = newTemp(g, wU32)
      let dv = newTemp(g, w)
      let ov = newTemp(g, w)
      g.outp.openTree Seq
      g.setLocal pv:
        g.genExprCoerced(t, wU32)                # pointer
        skip t
      g.setLocal dv:
        g.genExprCoerced(t, w)                   # operand
        skip t
      while t.hasMore: skip t                    # memorder
      g.setLocal ov:
        g.hloadOf(w, pv)
      g.outp.tree HStore:
        g.outp.width w
        g.outp.symUse pv
        g.outp.tree op:
          g.outp.width w
          g.outp.symUse ov
          g.outp.symUse dv
      if wantValue: g.outp.symUse ov
      g.outp.closeTag
    of AtomicExchangeOp:
      # (ptr, val, order) → the old value. A single-threaded swap.
      var pT = lengType(g, t)
      let elemT = innerType(g.prog, resolveType(g.prog, pT))
      let w = widthOf(scalOf(g, elemT))
      let pv = newTemp(g, wU32)
      let vv = newTemp(g, w)
      let ov = newTemp(g, w)
      g.outp.openTree Seq
      g.setLocal pv:
        g.genExprCoerced(t, wU32)                # pointer
        skip t
      g.setLocal vv:
        g.genExprCoerced(t, w)                   # value
        skip t
      while t.hasMore: skip t                    # memorder
      g.setLocal ov:
        g.hloadOf(w, pv)
      g.outp.tree HStore:
        g.outp.width w
        g.outp.symUse pv
        g.outp.symUse vv
      if wantValue: g.outp.symUse ov
      g.outp.closeTag
    of AtomicCompareExchangeOp:
      # (ptr, expected_ptr, desired, weak, succ_order, fail_order) → bool.
      # Single-threaded: if *ptr == *expected { *ptr = desired; true }
      #                  else { *expected = *ptr; false }
      var pT = lengType(g, t)
      let elemT = innerType(g.prog, resolveType(g.prog, pT))
      let w = widthOf(scalOf(g, elemT))
      let pv = newTemp(g, wU32)
      let ev = newTemp(g, wU32)
      let dv = newTemp(g, w)
      let cv = newTemp(g, w)
      g.outp.openTree Seq
      g.setLocal pv:
        g.genExprCoerced(t, wU32)                # ptr
        skip t
      g.setLocal ev:
        g.genExprCoerced(t, wU32)                # expected: a POINTER
        skip t
      g.setLocal dv:
        g.genExprCoerced(t, w)                   # desired
        skip t
      while t.hasMore: skip t                    # weak + memorders
      g.setLocal cv:
        g.hloadOf(w, pv)
      g.outp.openTree Cond
      g.outp.tree Eq:
        g.outp.width w
        g.outp.symUse cv
        g.hloadOf(w, ev)
      g.outp.tree Seq:
        g.outp.tree HStore:
          g.outp.width w
          g.outp.symUse pv
          g.outp.symUse dv
        g.outp.lit TrueLit
      g.outp.tree Seq:
        g.outp.tree HStore:
          g.outp.width w
          g.outp.symUse ev
          g.outp.symUse cv
        g.outp.lit FalseLit
      g.outp.closeTag                            # Cond
      g.outp.closeTag                            # Seq
    of CtzOp, ClzOp, PopcountOp:
      # The portable bit rows: the count, moved to the declared return width.
      # `litWidth` is the suffix-aware width: getType on a `suf` literal
      # reports the inner literal's natural type and would pick the 32-bit
      # count for a `(suf … "i64")` operand.
      let big = widthBits(litWidth(g, t)) >= 64
      let rw = widthOf(scalOf(g, lengType(g, c)))
      if rw != wI32:
        g.outp.openTree Cvt
        g.outp.width wI32
        g.outp.width rw
      g.outp.openTree(case it.op
                      of CtzOp: Ctz
                      of ClzOp: Clz
                      else: Popcnt)
      let ow = if big: wU64 else: wU32
      g.outp.width ow
      g.genExprCoerced(t, ow)
      skip t
      while t.hasMore: skip t                    # a trailing operand, drained
      g.outp.closeTag
      if rw != wI32: g.outp.closeTag
    of CpuRelaxOp:
      # A spin-wait hint: a single-threaded target has nobody to wait for.
      while t.hasMore: skip t
      g.outp.numLit 0
    else:
      err g, "(instr …) not lowered by the web back end: " & $it.op

proc importjsTemplate(decl: Cursor): string =
  ## The `{.importjs: "tpl".}` splice template, carried in the proc's pragma
  ## list as `(importjs "tpl")`. Only meaningful once the caller has confirmed
  ## `hasPragma(decl, ImportjsP)`; a genuinely empty template splices to nothing.
  ## A read-only walk (`sub`, not `into`): nothing here mutates the tree, so it
  ## must not claim the children `into` would demand be consumed.
  result = ""
  var d = sub(decl)                            # the proc's children
  skip d                                       # name
  skip d                                       # params
  skip d                                       # result type
  if d.kind == TagLit:                         # the pragma list
    var p = sub(d)
    while p.hasMore:
      if p.kind == TagLit and p.pragmaKind == ImportjsP:
        var a = sub(p)                         # (importjs "tpl")
        if a.kind == StrLit: result = strVal(a)
      skip p

proc proctypeSig(g: var WebGen; pt: Cursor): (seq[Cursor], Cursor) =
  ## The parameter types and the return type of a `(proctype NAME PARAMS RET …)`.
  ## Read-only (`sub`): the cursors point into the caller's stable `decl` and are
  ## classified later, so nothing here may consume the tree.
  var params: seq[Cursor]
  var p = sub(pt)
  skip p                                     # NAME
  if p.kind == TagLit and p.typeKind == ParamsT:
    var pp = sub(p)                          # each `(param NAME PRAGMAS TYPE …)`
    while pp.hasMore:
      var q = sub(pp)
      skip q                                 # NAME
      skip q                                 # PRAGMAS
      params.add q                           # TYPE
      skip pp
  skip p                                     # past PARAMS (a tag or a DotToken)
  (params, p)                                # p is now the RET child

proc operandProcSym(g: var WebGen; t: Cursor): SymId =
  ## The proc symbol a callback operand names: a bare proc Symbol, or one under
  ## `(addr …)`/`(haddr …)`. Empty when it is not a direct proc reference — a
  ## stored fn-ptr or a closure literal — which a bridged wrapper cannot target.
  var c = t
  while c.kind == TagLit and c.exprKind in {AddrC, HaddrC}:
    inc c
  if c.kind == Symbol and lookupSym(typeCtx(g), symName(c)).cat == scProc:
    result = symId(c)

proc callbackBridge(g: var WebGen; t: Cursor; pt: Cursor) =
  ## Emit a JS callable for a Nim proc used as an `importjs` callback (rAF,
  ## setTimeout, a DOM listener). The JS host calls it with plain JS values; we
  ## bridge each argument and the result by kind and invoke the Nim proc, which
  ## jorogumo emits as an ordinary JS function taking its declared parameters.
  ## A proc whose signature is all-scalar with a void/scalar result is already
  ## JS-callable, so it passes through as the table entry `FTAB[i]`; anything
  ## needing a handle/string bridge gets a generated wrapper around it.
  let (ptypes, ret) = proctypeSig(g, pt)
  var argExprs: seq[string] = @[]
  var bridged = false
  for i, pty in ptypes:
    let a = "a[" & $i & "]"
    case jsBridgeKind(g, pty)
    of jbNone:
      if isAggType(g, pty):
        # An aggregate (a `WGPUStringView`, say) travels as the address of a
        # materialized copy — the same rule `genCallArgs` uses for ordinary
        # calls. A host that fires such a callback must hand over that
        # address, which is exactly what the Nim-side fire splices do (they
        # pass `cast[int](addr sv)`); a raw JS object here would be garbage,
        # but no host we control does that.
        discard
      argExprs.add a
    of jbHandle:
      # A host that hands over a JS object gets an EXT handle for it. A
      # number is already a raw value — a Nim address (userdata) or an
      # interned handle — and must pass through untouched, so a pointer a
      # Nim caller stored in `userdata` arrives as the same pointer.
      argExprs.add "(typeof " & a & " === \"object\" && " & a &
                   " !== null ? ewrap(" & a & ") : " & a & ")"
      bridged = true
    of jbString:  argExprs.add "jsToNimStr(" & a & ")"; bridged = true
    of jbCstring: argExprs.add "jsToCstr(" & a & ")"; bridged = true
    of jbCallback: err g, "a JS callback cannot take a Nim callback parameter"
  var retBridge = ""
  case jsBridgeKind(g, ret)
  of jbNone:
    if not ret.cursorIsNil and ret.kind != DotToken and isAggType(g, ret):
      err g, "a JS callback cannot return an aggregate struct"
  of jbHandle:  retBridge = "eunwrap"; bridged = true
  of jbString:  retBridge = "nimStrToJs"; bridged = true
  of jbCstring: retBridge = "cstrToJs"; bridged = true
  of jbCallback: err g, "a JS callback cannot return a Nim callback"

  if not bridged:
    # Already JS-callable: hand over the function the table holds. Works for a
    # symbol or a stored fn-ptr — the index is whatever the operand evaluates to.
    g.outp.openTree Index
    g.outp.ident "FTAB"
    genExpr(g, t)
    g.outp.closeTag
    return
  # A wrapper bridges the JS call to the Nim proc. A named proc bakes its slot
  # in; a stored fn-ptr (a `callbackInfo.callback` field, a slot variable) is
  # bridged around the value the operand evaluates to — `FTAB[h]` is the Nim
  # proc itself, so only the arguments need converting. A capturing closure
  # stays out of reach: jorogumo carries no environment.
  let sym = operandProcSym(g, t)
  if sym == SymId(0):
    let w = "__cb" & $g.callbacks.len
    var dynCall = "slot(" & argExprs.join(", ") & ")"
    if retBridge.len > 0: dynCall = retBridge & "(" & dynCall & ")"
    g.callbacks.add "function " & w & "(slot) { return (...a) => " & dynCall &
                    "; }\n"
    g.outp.openTree Call
    g.outp.ident w
    g.outp.openTree Index
    g.outp.ident "FTAB"
    genExpr(g, t)
    g.outp.closeTag
    g.outp.closeTag
    return
  var found = false
  let cdecl = procDeclOf(g, sym, found)
  if not found: err g, "unknown callback proc: " & poolSym(g.lengPool, sym)
  ensureProc(g, sym, cdecl)
  let w = "__cb" & $g.callbacks.len
  var call = poolSym(g.irPool, irName(g, sym)) & "(" & argExprs.join(", ") & ")"
  if retBridge.len > 0: call = retBridge & "(" & call & ")"
  # Rest args so the JS host may pass more (rAF's timestamp) than the Nim proc
  # declares; the extras are simply not forwarded.
  g.callbacks.add "function " & w & "(...a) { return " & call & "; }\n"
  g.outp.ident w

proc genCallArgs(g: var WebGen; decl: Cursor; t: var Cursor; splice = false) =
  ## Emit each argument from `t`, moved to the width `decl`'s parameter declares
  ## (aggregates travel as the address of a copy). A varargs tail past the
  ## declared parameters rides along, still copied. `t` ends past the last
  ## argument. Shared by the ordinary `Call` and the `importjs` `Raw` splice —
  ## pass-by-value does not depend on the calling convention.
  ##
  ## `splice` marks the `importjs` case: a pointer-typed (handle) parameter
  ## unwraps to the real JS value (`eunwrap`) so the template splices the object,
  ## not its handle. A `Call` never unwraps — there a pointer is a real address.
  var p = decl
  p.into:
    inc p                                    # name
    p.into:                                  # params
      while p.hasMore:
        var q = p
        var w = wU32
        var agg = false
        var bk = jbNone
        var ptq: Cursor                      # the proctype of a callback parameter
        q.into:
          inc q                              # name
          skip q                             # pragmas
          agg = isAggType(g, q)
          if splice:
            bk = jsBridgeKind(g, q)
            if bk == jbCallback:
              # The declared type may be a named alias or a `ptr proctype`;
              # resolve both layers to the signature itself (calleeProctype's
              # rule) so `proctypeSig` enters a TagLit.
              ptq = resolveType(g.prog, q)
              if ptq.kind == TagLit and ptq.typeKind != ProctypeT:
                var inner = ptq
                inc inner
                ptq = resolveType(g.prog, inner)
          if not agg: w = widthOf(g, q)
          while q.hasMore: skip q
        skip p
        if t.hasMore:
          case bk
          of jbString:                       # Nim SSO string -> JS string
            g.outp.openTree Call
            g.outp.ident "nimStrToJs"
            genExpr(g, t)                    # an aggregate's value IS its address
            g.outp.closeTag
          of jbCstring:                      # NUL-terminated bytes -> JS string
            g.outp.openTree Call
            g.outp.ident "cstrToJs"
            g.genExprCoerced(t, wU32)
            g.outp.closeTag
          of jbHandle:                       # handle -> the JS value it names
            g.outp.openTree EUnwrap
            g.genExprCoerced(t, w)
            g.outp.closeTag
          of jbCallback:                     # Nim proc -> a JS callable
            callbackBridge(g, t, ptq)
          of jbNone:
            let (csz, _) = aggArgDestSize(g, t)
            if csz > 0: genAggArg(g, t, csz)
            elif agg: genExpr(g, t)
            else: g.genExprCoerced(t, w)
          skip t
    while p.hasMore: skip p                # result type, pragmas, body
  # anything past the declared parameters (a varargs tail) rides along,
  # aggregates still copied: pass-by-value does not depend on the signature
  while t.hasMore:
    let (csz, _) = aggArgDestSize(g, t)
    if csz > 0: genAggArg(g, t, csz)
    else: genExpr(g, t)
    skip t

proc declSignature(g: var WebGen; decl: Cursor): WebImport =
  ## The IR signature of a `(proc …)` decl: an aggregate parameter travels as
  ## its address, an aggregate result through a hidden first parameter whose
  ## address comes back as the result.
  var d = decl
  d.into:
    inc d                                      # name
    var rt: Cursor
    var ps: seq[WidthCode] = @[]
    if d.kind == TagLit:
      var pc = d
      pc.into:
        while pc.hasMore:
          var q = pc
          q.into:
            inc q                              # name
            skip q                             # pragmas
            ps.add paramWidth(g, q)
            while q.hasMore: skip q
          skip pc
    skip d                                     # params
    rt = d
    result.ret = resultWidth(g, rt, result.hasRet)
    if result.hasRet and isAggType(g, rt): result.params.add wU32
    result.params.add ps
    while d.hasMore: skip d

proc hostImport(g: var WebGen; sym: SymId; decl: Cursor): SymId =
  ## The host import a bodyless `importc` proc binds to, keyed by its C name:
  ## several Nim declarations may bind one C function.
  var icName, ecName = ""
  var d = decl
  d.into:
    inc d                                      # name
    skip d                                     # params
    skip d                                     # result
    parsePragmas(d, icName, ecName)
    while d.hasMore: skip d
  if icName.len == 0: icName = poolSym(g.lengPool, sym)
  if g.importOf.hasKey(icName): return g.importOf[icName]
  var imp = declSignature(g, decl)
  imp.name = icName
  if icName in [ImpWrite, ImpExit, GlobErrv, GlobOvf, MemcmpFunc]:
    err g, "host import `" & icName & "` collides with the runtime floor"
  g.imports.add imp
  result = g.irPool.syms.getOrIncl(icName)
  g.importOf[icName] = result

proc genCallFrom(g: var WebGen; t: var Cursor; wantValue: bool) =
  ## The call lowering, entered with `t` AT the target child and the args
  ## after it; `t` ends past the last argument. `genCall` walks into the call
  ## node and hands over; `genOnerr` starts here directly, because an `onerr`
  ## node's call shares its head with the action.
  let target = t
  var indirect = true
  var nm = ""
  var nmSym = SymId(0)
  var ct: CallTarget
  var known = false
  if t.kind == Symbol:
    nm = symName(t)
    nmSym = symId(t)
    # classify a foreign callee BEFORE dispatching: the typenav target says
    # whether it is a syscall, an extern, or an ordinary proc — the same
    # lazy resolution `getType` performs for the call's type.
    if not g.callTarget.hasKey(nm) and isForeignSym(g.prog, nm):
      var fnd = false
      let fd = lookupForeignDecl(g.prog, nm, fnd)
      if fnd and fd.stmtKind == ProcS:
        g.callTarget[nm] = foreignCallTarget(g.prog, nm)
    if g.callTarget.hasKey(nm):
      ct = g.callTarget[nm]
      known = true
    # a Symbol that is not a proc decl — a local, param or proc-typed
    # global holding a fn-ptr — dispatches through the table. arkham's
    # `isIndirectCallTarget` follows the same rule.
    indirect = lookupSym(typeCtx(g), nm).cat != scProc
    inc t                                    # a Symbol is one token: now at the args
  else:
    skip t                                   # a tree callee: PAST the subtree,
                                             # `inc` would step into it
  if known and ct.syscall:
    # The syscall's C name is encoded in the target's asmName as
    # `` <c>`sys.0.<mod> `` (arkham #165 put the role in the identifier);
    # `cNameOfAsmName` strips the backtick role tag. ithaqua's twin rule.
    var base = nm
    if ct.asmName.len > 0: base = cNameOfAsmName(ct.asmName)
    genSyscall(g, base, target, t, wantValue)
  elif known and ct.memIntrin.len > 0:
    genMemIntrin(g, ct.memIntrin, t, wantValue)
  elif known and ct.bitBuiltin.len > 0:
    # The GCC bit builtins are the `instr` bit rows spelled as calls, and the
    # page pair is the linear memory's own size/grow. GCC returns `int`, so the
    # count IS the canonical result. Anything else is refused by name.
    case ct.bitBuiltin
    of "__builtin_ctz", "__builtin_clz", "__builtin_popcount",
       "__builtin_ctzll", "__builtin_clzll", "__builtin_popcountll":
      let ll = ct.bitBuiltin.endsWith("ll")
      g.outp.openTree(case ct.bitBuiltin
                      of "__builtin_ctz", "__builtin_ctzll": Ctz
                      of "__builtin_clz", "__builtin_clzll": Clz
                      else: Popcnt)
      let ow = if ll: wU64 else: wU32
      g.outp.width ow
      g.genExprCoerced(t, ow)
      skip t
      while t.hasMore: skip t
      g.outp.closeTag
    of "__builtin_wasm_memory_size":
      g.outp.lit MemSize
      while t.hasMore: skip t                # zero args, drain defensively
    of "__builtin_wasm_memory_grow":
      g.outp.openTree MemGrow
      g.genExprCoerced(t, wI32)
      skip t
      while t.hasMore: skip t
      g.outp.closeTag
    else:
      err g, "bit builtin `" & ct.bitBuiltin & "` has no web lowering"
  elif indirect:
    genIndirectCall(g, target, t)
  else:
    var found = false
    let decl = procDeclOf(g, nmSym, found)
    if found and not hasBody(decl) and hasPragma(decl, ImportjsP):
      if g.target != wtJs:
        err g, "`importjs` proc `" & nm & "` has no wasm lowering"
      # A bodyless `importjs` proc splices its JS template at the call site:
      # emit `(raw NAME "tpl" ARG…)` and let the renderer substitute the
      # operands. No function is emitted — the template IS the call, so the
      # NAME is only the `$1`/`$#` label, never a reference to a lowered proc.
      # The result is bridged by kind: a JS string becomes a Nim `string`
      # (`jsToNimStr`) or a `cstring` (`jsToCstr`); a pointer (handle) is a
      # real JS value the splice produced, so it wraps back into the host
      # table (`ewrap`); scalars pass through as the splice's own number.
      let rt = calleeResultType(g, target)
      let rbk = if not rt.cursorIsNil: jsBridgeKind(g, rt) else: jbNone
      case rbk
      of jbString:
        g.outp.openTree Call
        g.outp.ident "jsToNimStr"
      of jbCstring:
        g.outp.openTree Call
        g.outp.ident "jsToCstr"
      of jbHandle:
        g.outp.openTree EWrap
      of jbNone: discard
      of jbCallback:
        # A splice handing a JS function back to Nim would need the reverse
        # bridge (a JS callable stored as a table-shaped value); nothing needs
        # it yet, and a silent no-wrap would miscompile. Refuse, per the rule.
        err g, "an importjs splice cannot yet return a Nim callback"
      g.outp.openTree Raw
      g.outp.ident nm
      g.outp.strLit importjsTemplate(decl)
      genCallArgs(g, decl, t, splice = true)
      g.outp.closeTag
      if rbk != jbNone: g.outp.closeTag
    elif (known and ct.extern or found and isHostDeclaration(decl)) and
        not (found and hasBody(decl)):
      # An `importc`/`importcpp` WITH a body is an ordinary definition — the C
      # compiler emits bodies for its importcs too; only the bodyless signature
      # reaches across to the host. In host-imports mode it becomes an import
      # the page provides; otherwise it is refused here, not emitted as an
      # empty stub that silently returns nothing.
      if not (found and g.hostImports):
        err g, "extern `" & nm & "` has no host binding (bodyless importc)"
      let imp = hostImport(g, nmSym, decl)
      let rt = calleeResultType(g, target)
      let aggRet = not rt.cursorIsNil and isAggType(g, rt)
      g.outp.openTree Call
      g.outp.symUse imp
      if aggRet: slotAddr(g, takeTemp(g, byteSize(g, rt), "sret"))
      genCallArgs(g, decl, t)
      g.outp.closeTag
    else:
      if not found: err g, "no body to call: " & nm
      ensureProc(g, nmSym, decl)
      let rt = calleeResultType(g, target)
      let aggRet = not rt.cursorIsNil and isAggType(g, rt)
      g.outp.openTree Call
      g.outp.symUse irName(g, nmSym)
      # The struct-return destination is the CALLER's planned temporary, and it
      # is reserved before the arguments are walked: `planFrame` reserved it at
      # the call node, and any temporary an argument needs comes after it.
      if aggRet: slotAddr(g, takeTemp(g, byteSize(g, rt), "sret"))
      genCallArgs(g, decl, t)
      g.outp.closeTag

proc genCall(g: var WebGen; c: Cursor; wantValue: bool) =
  var t = c
  t.into:
    genCallFrom(g, t, wantValue)

# ── statements ───────────────────────────────────────────────────────────────

proc genVar(g: var WebGen; c: Cursor) =
  ## `(var :name PRAGMAS TYPE INIT?)`. A plain scalar is a function local,
  ## declared with the function and assigned here. An aggregate or an
  ## address-taken local has no local to point at: `planFrame` gave it a slot,
  ## and its initializer becomes a store into that slot.
  var nm = ""
  var initv: Cursor
  var hasInit = false
  var t = c
  t.into:
    nm = symName(t)
    inc t
    skip t                                     # pragmas
    skip t                                     # the type: planFrame recorded it
    if t.hasMore and t.kind != DotToken:
      initv = t
      hasInit = true
    while t.hasMore: skip t
  if not g.p.locals.hasKey(nm): err g, "internal: unplanned local `" & nm & "`"
  let sl = g.p.locals[nm]
  case sl.kind
  of lkReg:
    # The binding came from the prologue; this statement only gives it its value.
    # With no initializer the hoisted zero already is the answer.
    if hasInit:
      let w = widthOf(scalOf(g, g.p.symType[nm]))
      g.outp.tree ExprStmt:
        g.outp.tree Assign:
          g.outp.symUse irName(g, nm)
          g.genExprCoerced(initv, w)
  of lkSlot:
    let ty = g.p.symType[nm]
    if isAggType(g, ty):
      if hasInit:
        if initv.kind == TagLit and initv.exprKind in {OconstrC, AconstrC}:
          g.outp.tree ExprStmt: genCtorInto(g, sl.off, initv)
        else:
          g.outp.tree ExprStmt: copyToSlot(g, sl.off, initv, byteSize(g, ty))
    elif not hasInit:
      # The slot must not carry whatever the previous frame left there: an
      # uninitialized address-taken local reads as zero, as a wasm local does.
      g.outp.tree ExprStmt: zeroSlot(g, sl.off, byteSize(g, ty))
    else:
      let w = widthOf(scalOf(g, ty))
      g.outp.tree ExprStmt:
        g.outp.tree HStore:
          g.outp.width w
          slotAddr(g, sl.off)
          g.genExprCoerced(initv, w)
  of lkPtr: err g, "internal: `" & nm & "` is a parameter, not a local"

proc lvalueType(g: var WebGen; c: Cursor): Cursor =
  ## The type of the thing an lvalue denotes. Typenav answers the same question
  ## for an lvalue as for an rvalue, so `deref`/`dot`/`at`/`pat` need no case —
  ## but `baseobj` is not in typenav's grammar, so its declared type is read off
  ## the node.
  if c.kind == Symbol:
    let nm = symName(c)
    if g.p.locals.hasKey(nm): result = g.p.symType[nm]
    else: result = declType(g, nm)
  elif c.kind == TagLit and c.exprKind == BaseobjC:
    var t = c
    t.into:
      result = t
      while t.hasMore: skip t
  else:
    result = lengType(g, c)

proc assignTo(g: var WebGen; dst, src: Cursor) =
  ## One store, wherever the destination lives. Only a register local has no
  ## address to store through; every other destination — a frame slot, a
  ## global, a field, an element, a `deref` — reduces to an address, and an
  ## aggregate moves as a copy between two of them.
  if dst.kind == Symbol and g.p.locals.hasKey(symName(dst)) and
      g.p.locals[symName(dst)].kind == lkReg:
    let nm = symName(dst)
    g.outp.tree Assign:
      g.outp.symUse irName(g, nm)
      g.genExprCoerced(src, widthOf(scalOf(g, g.p.symType[nm])))
    return
  let ty = lvalueType(g, dst)
  if isAggType(g, ty):
    g.outp.openTree MemCopy
    genAddr(g, dst)
    genExpr(g, src)                            # an aggregate value IS an address
    g.outp.numLit int64(byteSize(g, ty))
    g.outp.closeTag
  else:
    let w = widthOf(scalOf(g, ty))
    g.outp.tree HStore:
      g.outp.width w
      genAddr(g, dst)
      g.genExprCoerced(src, w)

proc genAsgn(g: var WebGen; c: Cursor) =
  var t = c
  t.into:
    let dst = t
    skip t
    if dst.kind == TagLit and dst.exprKind in {ErrvC, OvfC}:
      # errv/ovf as destinations → the flag globals, like ithaqua's
      g.outp.tree ExprStmt:
        g.outp.openTree Assign
        g.outp.symUse(if dst.exprKind == OvfC: GlobOvf else: GlobErrv)
        g.genExprCoerced(t, wI32)
        g.outp.closeTag
      while t.hasMore: skip t
      return
    g.outp.tree ExprStmt: assignTo(g, dst, t)
    while t.hasMore: skip t

proc zeroLit(g: var WebGen; w: WidthCode) =
  ## A zero in the right world: a 64-bit slot holds a BigInt, and mixing the two
  ## is a JS type error, not a truncation.
  if w in {wI64, wU64}: g.outp.bigIntLit "0" else: g.outp.numLit 0

proc storeTempTo(g: var WebGen; dst: Cursor; tmp: SymId; w: WidthCode) =
  ## Store a materialized, already-canonical value into an lvalue — the store
  ## half of `assignTo` for the case where the value is a `let`-bound temp
  ## rather than a cursor, so no coercion is needed.
  if dst.kind == Symbol and g.p.locals.hasKey(symName(dst)) and
      g.p.locals[symName(dst)].kind == lkReg:
    g.outp.tree Assign:
      g.outp.symUse irName(g, symName(dst))
      g.outp.symUse tmp
    return
  let ty = lvalueType(g, dst)
  if isAggType(g, ty):
    err g, "keepovf destination is not an integer"
  g.outp.tree HStore:
    g.outp.width w
    genAddr(g, dst)
    g.outp.symUse tmp

proc ovfTest(g: var WebGen; opKind: LengExpr; sc: Scal; w: WidthCode;
             av, bv, rv: SymId) =
  ## The boolean overflow test over the bound temps: operands `av`, `bv` and
  ## the already-wrapped result `rv`.
  if sc.kind == skI32:
    # ithaqua's ≤32-bit move: compare the wrapped result against the WIDE one.
    # The wide world is BigInt — exact at these widths — and `cvt` moves the
    # operands there without loss; `!=` then bridges back by value.
    let bigW = if sc.signed: wI64 else: wU64
    let op = case opKind
             of AddC: Add
             of SubC: Sub
             else: Mul
    template cvtTo(v: SymId) =
      g.outp.openTree Cvt
      g.outp.width w
      g.outp.width bigW
      g.outp.symUse v
      g.outp.closeTag
    g.outp.openTree Neq
    g.outp.width bigW
    cvtTo rv
    g.outp.openTree op
    g.outp.width bigW
    cvtTo av
    cvtTo bv
    g.outp.closeTag
    g.outp.closeTag
    return
  # skI64: the classic identities, in BigInt — the same ones ithaqua emits.
  case opKind
  of AddC:
    if sc.signed:
      # ovf iff sign(a)==sign(b) and sign(r)!=sign(a): ((a^r)&(b^r)) < 0
      g.outp.openTree Lt
      g.outp.width w
      g.outp.openTree And
      g.outp.width w
      g.outp.openTree Xor
      g.outp.width w
      g.outp.symUse av
      g.outp.symUse rv
      g.outp.closeTag
      g.outp.openTree Xor
      g.outp.width w
      g.outp.symUse bv
      g.outp.symUse rv
      g.outp.closeTag
      g.outp.closeTag
      g.zeroLit w
      g.outp.closeTag
    else:
      g.outp.openTree Lt                       # carry: r < a
      g.outp.width w
      g.outp.symUse rv
      g.outp.symUse av
      g.outp.closeTag
  of SubC:
    if sc.signed:
      # ovf iff sign(a)!=sign(b) and sign(r)!=sign(a): ((a^b)&(a^r)) < 0
      g.outp.openTree Lt
      g.outp.width w
      g.outp.openTree And
      g.outp.width w
      g.outp.openTree Xor
      g.outp.width w
      g.outp.symUse av
      g.outp.symUse bv
      g.outp.closeTag
      g.outp.openTree Xor
      g.outp.width w
      g.outp.symUse av
      g.outp.symUse rv
      g.outp.closeTag
      g.outp.closeTag
      g.zeroLit w
      g.outp.closeTag
    else:
      g.outp.openTree Lt                       # borrow: a < b
      g.outp.width w
      g.outp.symUse av
      g.outp.symUse bv
      g.outp.closeTag
  else:
    # mul: ovf iff a != 0 and r/a != b. A signed division of min(i64) by -1
    # TRAPS in wasm (it has no representable result), so that one case is
    # decided without dividing: with a == -1 the product overflows exactly when
    # b is min(i64). BigInt would not trap, but one tree serves both targets.
    template quotientTest() =
      g.outp.tree Neq:
        g.outp.width w
        g.outp.tree Div:
          g.outp.width w
          g.outp.symUse rv
          g.outp.symUse av
        g.outp.symUse bv
    g.outp.openTree LAnd
    g.outp.width w
    g.outp.tree Neq:
      g.outp.width w
      g.outp.symUse av
      g.zeroLit w
    if sc.signed:
      g.outp.tree Cond:
        g.outp.tree Eq:
          g.outp.width w
          g.outp.symUse av
          g.outp.bigIntLit "-1"
        g.outp.tree Eq:
          g.outp.width w
          g.outp.symUse bv
          g.outp.bigIntLit "-9223372036854775808"
        quotientTest()
    else:
      quotientTest()
    g.outp.closeTag

proc genKeepovf(g: var WebGen; c: Cursor) =
  ## `(keepovf (add|sub|mul Type a b) dst)` — overflow-checked arithmetic:
  ## `(ovf, dst) = a op b`. The web targets have no flags register; `ovf` is a
  ## scalar global, and the wrapped result is the renderer's width-wrap.
  var t = c
  t.into:
    let arith = t
    skip t
    let dst = t
    skip t
    while t.hasMore: skip t
    var a = arith
    var opKind: LengExpr
    var typ, lhs, rhs: Cursor
    a.into:
      opKind = arith.exprKind
      typ = a
      skip a
      lhs = a
      skip a
      rhs = a
      skip a
      while a.hasMore: skip a
    if opKind notin {AddC, SubC, MulC}:
      err g, "keepovf on unsupported op: " & $opKind
    let sc = scalOf(g, typ)
    if sc.kind notin {skI32, skI64}:
      err g, "keepovf on a non-integer type"
    let w = widthOf(sc)
    let resOp = case opKind
                of AddC: Add
                of SubC: Sub
                else: Mul
    # Bind the operands and the wrapped result: the tests read each operand
    # twice, and the result serves both the test and the store.
    let av = newTemp(g, w)
    let bv = newTemp(g, w)
    let rv = newTemp(g, w)
    g.outp.tree ExprStmt:
      g.setLocal av:
        g.genExprCoerced(lhs, w)
    g.outp.tree ExprStmt:
      g.setLocal bv:
        g.genExprCoerced(rhs, w)
    g.outp.tree ExprStmt:
      g.setLocal rv:
        g.outp.openTree resOp
        g.outp.width w
        g.outp.symUse av
        g.outp.symUse bv
        g.outp.closeTag
    g.outp.tree ExprStmt:
      g.outp.openTree Assign
      g.outp.symUse GlobOvf
      g.outp.openTree Cond
      ovfTest(g, opKind, sc, w, av, bv, rv)
      g.outp.numLit 1
      g.outp.numLit 0
      g.outp.closeTag
      g.outp.closeTag
    g.outp.tree ExprStmt:
      storeTempTo(g, dst, rv, w)

proc leaveFrame(g: var WebGen) =
  ## Pop the shadow stack. Every `return` leaves first, and the epilogue leaves
  ## for the paths that fall off the end, so each path pops exactly once.
  if g.p.frameSize > 0:
    g.outp.lit Leave

proc genRet(g: var WebGen; c: Cursor) =
  var src: Cursor
  var hasVal = false
  var t = c
  t.into:
    if t.kind != DotToken:
      src = t
      hasVal = true
    while t.hasMore: skip t
  if not hasVal:
    leaveFrame(g)
    g.outp.openTree Return
    g.outp.closeTag
    return
  if isAggType(g, g.p.retType):
    # The destination is the CALLER's slot, handed in as the hidden first
    # argument, so it outlives this frame and may be returned after the pop.
    g.outp.tree ExprStmt:
      g.outp.openTree MemCopy
      g.outp.symUse g.p.sretName
      genExpr(g, src)
      g.outp.numLit int64(byteSize(g, g.p.retType))
      g.outp.closeTag
    leaveFrame(g)
    g.outp.tree Return: g.outp.symUse g.p.sretName
  else:
    # The value may be read out of this very frame, so it is computed before
    # the pop and parked in a binding of its own.
    let rw = widthOf(g, g.p.retType)
    let r = newTemp(g, rw)
    g.outp.tree ExprStmt:
      g.setLocal r:
        g.genExprCoerced(src, rw)
    leaveFrame(g)
    g.outp.tree Return: g.outp.symUse r

proc genStmt(g: var WebGen; c: var Cursor)   # mutually recursive with genCase

proc widthLit(g: var WebGen; w: WidthCode; v: int64) =
  ## A constant in the scrutinee's world: BigInt for the 64-bit widths, Number
  ## for the rest, so a comparison never straddles the two.
  if w in {wI64, wU64}: g.outp.bigIntLit $v
  else: g.outp.numLit v

proc caseValue(g: var WebGen; r: Cursor): int64 =
  ## The literal a case branch selects on. Only numbers and chars are labels;
  ## anything else (a symbol constant, a range of them) is refused rather than
  ## guessed at.
  case r.kind
  of IntLit: intVal(r)
  of CharLit: int64(ord(charLit(r)))
  else:
    err g, "unsupported case label: " & $r.kind

proc caseRangeTest(g: var WebGen; w: WidthCode; scrutinee: SymId; r: Cursor) =
  ## One `BranchRange` — a value, or `(range LO HI)` — as a test on the bound
  ## scrutinee.
  if r.kind == TagLit and r.substructureKind == RangeU:
    var lo, hi: Cursor
    var t = r
    t.into:
      lo = t
      skip t
      hi = t
      while t.hasMore: skip t
    g.outp.openTree LAnd
    g.outp.width wI32                       # vacuous, but every op node carries one
    g.outp.openTree Le
    g.outp.width w
    widthLit(g, w, caseValue(g, lo))
    g.outp.symUse scrutinee
    g.outp.closeTag
    g.outp.openTree Le
    g.outp.width w
    g.outp.symUse scrutinee
    widthLit(g, w, caseValue(g, hi))
    g.outp.closeTag
    g.outp.closeTag
  else:
    g.outp.openTree Eq
    g.outp.width w
    g.outp.symUse scrutinee
    widthLit(g, w, caseValue(g, r))
    g.outp.closeTag

proc genCaseBranch(g: var WebGen; w: WidthCode; scrutinee: SymId;
                   branches: seq[(Cursor, Cursor)]; elseBody: Cursor; i: int) =
  ## The `of` branches from `i` on, as an `if / else if / else` chain. A JS
  ## `switch` (or a wasm `br_table`) is the obvious spelling but the wrong one: its `break` would
  ## capture a `(break)` that belongs to an enclosing loop, and it cannot say
  ## `(range LO HI)` at all.
  var rs: seq[Cursor]
  var t = branches[i][0]
  t.into:
    while t.hasMore:
      rs.add t
      skip t
  if rs.len == 0: err g, "empty `ranges` in a case branch"
  g.outp.openTree If
  # `c0 || (c1 || c2)`: each `||` wraps everything to its right, so the tests
  # are emitted between the opens and the closes.
  for j in 0 ..< rs.len:
    if j < rs.len - 1:
      g.outp.openTree LOr
      g.outp.width wI32                      # vacuous, but every op node carries one
    caseRangeTest(g, w, scrutinee, rs[j])
  for j in 0 ..< rs.len - 1: g.outp.closeTag
  var body = branches[i][1]
  genStmt(g, body)
  if i + 1 < branches.len:
    g.outp.openTree Else
    genCaseBranch(g, w, scrutinee, branches, elseBody, i + 1)
    g.outp.closeTag
  elif not elseBody.cursorIsNil and elseBody.kind == TagLit:
    g.outp.openTree Else
    var eb = elseBody
    genStmt(g, eb)
    g.outp.closeTag
  g.outp.closeTag

proc genCase(g: var WebGen; c: Cursor) =
  ## `(case E (of (ranges BR+) STMTS)* (else STMTLIST)?)`. The discriminant is
  ## evaluated ONCE into a binding, because every branch tests it.
  var branches: seq[(Cursor, Cursor)]
  var elseBody: Cursor
  var scrutinee: Cursor
  var t = c
  t.into:
    scrutinee = t
    skip t
    while t.hasMore:
      if t.kind == TagLit and t.substructureKind == OfU:
        var o = t
        o.into:
          let rg = o
          skip o
          if o.kind != TagLit or o.stmtKind != StmtsS:
            err g, "case branch without a statement list"
          branches.add (rg, o)
          while o.hasMore: skip o
      elif t.kind == TagLit and t.substructureKind == ElseU:
        elseBody = t
      skip t
  if not elseBody.cursorIsNil and elseBody.kind == TagLit:
    # `(else STMTLIST)` is a SUBSTRUCTURE; the statements are its child.
    elseBody = elseBody.sub()
  let ty = lengType(g, scrutinee)
  if isAggType(g, ty): err g, "case on an aggregate discriminant"
  let w = widthOf(scalOf(g, ty))
  if branches.len == 0:
    if not elseBody.cursorIsNil and elseBody.kind == TagLit:
      var eb = elseBody
      genStmt(g, eb)
    return
  let sw = newTemp(g, w)
  g.outp.tree ExprStmt:
    g.setLocal sw:
      g.genExprCoerced(scrutinee, w)
  genCaseBranch(g, w, sw, branches, elseBody, 0)


proc genIf(g: var WebGen; c: Cursor) =
  ## `(if (elif COND ACTION)* (else ACTION)?)` → an `if/else` chain. The IR has
  ## no `elif`, so every branch after the first is `else { if … }`; `open` counts
  ## the trees still waiting for their close, which the buffer unwinds LIFO.
  var open = 0
  var seen = false
  var t = c
  t.into:
    while t.hasMore:
      let isElif = t.kind == TagLit and t.substructureKind == ElifU
      let isElse = t.kind == TagLit and t.substructureKind == ElseU
      if not isElif and not isElse: err g, "malformed `if`"
      if seen:
        g.outp.openTree Else
        inc open
      if isElif:
        g.outp.openTree If
        inc open
      var e = t
      e.into:
        if isElif:
          genExpr(g, e)                          # the condition
          skip e
        genStmt(g, e)                            # the action: one (stmts …)
      seen = true
      skip t
    while open > 0:
      g.outp.closeTag
      dec open

proc landingPadLabel(c: Cursor): SymId =
  ## Non-empty iff `c` is hexer's jump-into-guarded-region idiom — the flag
  ## model's exception landing pad:
  ##
  ##   (if (elif (false) (stmts (lab L) …)))
  ##
  ## C's `if (0) { L: … }`. The try body `jmp`s INTO the guarded branch, so a
  ## plain if-lowering could never reach the label; `genStmtList` restructures
  ## it instead (ithaqua's `landingPadLabel`, ported).
  result = SymId(0)
  if c.stmtKind != IfS: return
  var t = c
  var lab = SymId(0)
  var arms = 0
  t.into:
    while t.hasMore:
      inc arms
      if arms == 1 and t.substructureKind == ElifU:
        var e = t
        e.into:
          if e.kind == TagLit and e.exprKind == FalseC:
            skip e                             # (false)
            if e.hasMore and e.stmtKind == StmtsS:
              var s = e
              s.into:
                if s.hasMore and s.stmtKind == LabS:
                  var l = s
                  l.into:
                    lab = symId(l)
                    while l.hasMore: skip l
                while s.hasMore: skip s
          while e.hasMore: skip e
      skip t
  if arms == 1: result = lab

proc genStmtList(g: var WebGen; c: Cursor) =
  ## `(stmts …)` / `(scope …)`: a JS block, wrapped in one labeled block per
  ## `(lab L)` the list declares. `jmp L` lowers to `break L`, and a `break`
  ## resumes right after L's block — which is why the `(lab L)` statement itself
  ## CLOSES that block rather than the end of the list. wasm has to nest these in
  ## reverse close order because `end` is positional; a JS label is named, so
  ## ordinary order is enough.
  ##
  ## A landing-pad child `(if (elif (false) (stmts (lab L) …)))` gets the twin
  ## of ithaqua's restructure: TWO blocks open at the head of the list —
  ##
  ##   $join: { $L: { …try children…; break $join }  …guarded body…  }
  ##
  ## `jmp L` inside the try children breaks past $L's end — which is the
  ## `(lab L)` marker inside the guarded child, so it lands on the handler —
  ## and normal fallthrough breaks to $join, skipping it. The blocks close in
  ## reverse event order: the `(lab)` markers and pad children appear in the
  ## order their regions end, so the first event opens innermost.
  g.outp.openTree Block
  let mark = g.p.labs.len
  # (isPad, the label's IR name) in child order. The IR name is the one the
  # blocks are keyed by: a Leng label and a generated join are both blocks
  # here, and their pool ids come from DIFFERENT pools.
  var events: seq[(bool, SymId)] = @[]
  var scan = c
  scan.into:
    while scan.hasMore:
      if scan.stmtKind == LabS:
        var l = scan
        l.into:
          let nm = irName(g, symId(l))
          if nm notin g.p.labs: events.add (false, nm)
          while l.hasMore: skip l
      else:
        let pl = landingPadLabel(scan)
        if pl != SymId(0):
          let ir = irName(g, pl)
          if ir notin g.p.labs: events.add (true, ir)
      skip scan
  var padJoin = initTable[SymId, SymId]()      # pad label -> its $join block
  for i in countdown(events.len - 1, 0):
    let (isPad, nm) = events[i]
    if isPad:
      let join = tmpName(g)
      padJoin[nm] = join
      g.outp.openTree Label
      g.outp.symUse join
      g.p.labs.add join
    g.outp.openTree Label
    g.outp.symUse nm
    g.p.labs.add nm
  var t = c
  t.into:
    while t.hasMore:
      let plLeng = landingPadLabel(t)
      let pl = if plLeng != SymId(0): irName(g, plLeng) else: SymId(0)
      if pl != SymId(0) and padJoin.hasKey(pl):
        # normal fallthrough skips the guarded body:
        g.outp.openTree Break
        g.outp.symUse padJoin[pl]
        g.outp.closeTag
        # Descend into the guarded branch and emit its `(stmts …)` children
        # INLINE — not through genStmtList, whose own Block would sit between
        # $L and its `(lab)` marker. The marker closes the $L block opened at
        # the head of THIS list, so a `break L` from the try children lands
        # exactly on the handler.
        var f = t
        f.into:
          var e = f
          e.into:                              # (elif
            skip e                             # (false)
            var s = e                          # (stmts (lab L) …)
            s.into:                            # the CHILDREN, not the node:
              while s.hasMore: genStmt(g, s)   # a nested Block would shield the
                                               # `(lab)` marker from closing $L
            skip e
            while e.hasMore: skip e
          skip f
          while f.hasMore: skip f
        # The `(lab L)` marker popped $L; $join closes right after the pad,
        # not at the end of the list — the siblings that follow must run on
        # the path the fallthrough break skips past the HANDLER only.
        if g.p.labs.len == 0 or g.p.labs[^1] != padJoin[pl]:
          err g, "landing pad body did not close its `$L` block"
        discard g.p.labs.pop()
        g.outp.closeTag
        skip t          # the descent consumed the child; `genStmt` would have
                        # skipped it, and re-lowering the pad would double-close
      else:
        genStmt(g, t)
  # A list whose `(lab)` marker never ran into this level (a pad's label, closed
  # by an inner list) leaves nothing to close here; the `>` guard keeps that safe.
  while g.p.labs.len > mark:
    discard g.p.labs.pop()
    g.outp.closeTag
  g.outp.closeTag

proc genOnerr(g: var WebGen; c: Cursor) =
  ## `(onerr ACTION FN ARGS…)`: perform the call for effect; if the `errv`
  ## global is set, run the ACTION (typically a `jmp` to the landing pad).
  ## A `.` action means "propagate by hand later". The call is lowered by
  ## `genCallFrom` — sret destination, aggregate-argument copies, indirect
  ## and extern classification and the value plan's reservations all apply
  ## exactly as for a `(call …)` in statement position.
  var t = c
  t.into:
    var act = t
    skip t                                     # the action is a statement
    g.outp.tree ExprStmt:
      genCallFrom(g, t, wantValue = false)
    if act.kind != DotToken:
      g.outp.openTree If
      g.outp.symUse GlobErrv
      genStmt(g, act)                          # e.g. `break L`
      g.outp.closeTag
  # `genStmt` skips the statement it dispatched; `into` never leaks.

proc genStmt(g: var WebGen; c: var Cursor) =
  if c.kind == DotToken:
    # `.` in a statement list means nothing goes here — `(stmts .)` is a body
    # that is empty, not a statement to lower.
    skip c
    return
  case c.stmtKind
  of StmtsS, ScopeS: genStmtList(g, c)
  of VarS: genVar(g, c)
  of AsgnS: genAsgn(g, c)
  of KeepovfS: genKeepovf(g, c)
  of RetS: genRet(g, c)
  of IfS: genIf(g, c)
  of WhileS:
    g.outp.openTree While
    var t = c
    t.into:
      genExpr(g, t)                            # the condition
      skip t
      if t.kind != TagLit or t.stmtKind notin {StmtsS, ScopeS}:
        err g, "`while` without a statement list"
      genStmt(g, t)
      while t.hasMore: skip t
    g.outp.closeTag
  of LoopS:
    # `(loop PRE COND BODY AFTER?)`: PRE runs before every test, so the test
    # sits inside the loop; AFTER runs once, past it.
    g.outp.openTree While
    g.outp.lit TrueLit
    var t = c
    t.into:
      genStmt(g, t)                            # pre-condition block
      g.outp.tree If:
        g.outp.tree Not:
          g.outp.width wI32
          genExpr(g, t)
        g.outp.tree Break: discard
      skip t
      genStmt(g, t)                            # body
      g.outp.closeTag                          # While
      if t.hasMore: genStmt(g, t)              # the `after` part
      while t.hasMore: skip t
  of BreakS:
    # An unnamed break: the innermost enclosing JS loop, which is the innermost
    # enclosing Leng loop because a `case` became an `if` chain.
    g.outp.openTree Break
    g.outp.closeTag
  of LabS:
    # The block opened for this label at the head of its list ends HERE, so a
    # `break` to it resumes at exactly this point.
    var nm = SymId(0)
    var t = c
    t.into:
      nm = irName(g, symId(t))
      while t.hasMore: skip t
    if g.p.labs.len == 0 or g.p.labs[^1] != nm:
      # Closing something else would strand a block that a later `jmp` still
      # needs, so this is a shape the generator does not understand.
      var open = ""
      for l in g.p.labs: open.add " " & poolSym(g.irPool, l)
      err g, "`lab` `" & poolSym(g.irPool, nm) &
            "` is not the innermost open label (open:" & open & ")"
    discard g.p.labs.pop()
    g.outp.closeTag
  of JmpS:
    var nm = SymId(0)
    var t = c
    t.into:
      nm = irName(g, symId(t))
      while t.hasMore: skip t
    if nm notin g.p.labs:
      err g, "`jmp` to `" & poolSym(g.irPool, nm) &
            "`, whose block does not enclose this point"
    g.outp.openTree Break
    g.outp.symUse nm
    g.outp.closeTag
  of CaseS: genCase(g, c)
  of OnerrS: genOnerr(g, c)
  of TryS, RaiseS:
    # ithaqua's refusal, kept: `eraiser` lowers every source-level `try` and
    # catchable `raise` to the flat `lab`/`jmp` form long before Leng, so one
    # of these in a body means a pass was skipped, not a feature to invent.
    err g, "C++-mode try/raise cannot appear in JavaScript Leng"
  of DiscardS:
    g.outp.tree ExprStmt:
      var t = c
      t.into:
        genExpr(g, t)
        while t.hasMore: skip t
  of CallS:
    g.outp.tree ExprStmt:
      genCall(g, c, wantValue = false)
  of InstrS:
    g.outp.tree ExprStmt:
      genInstr(g, c, wantValue = false)
  else: err g, "unsupported statement: " & $c.stmtKind
  skip c                                   # NOT `inc`: that would enter the tree

proc hasPragmaIn(pragmas: Cursor; want: LengPragma): bool =
  ## True when a `(pragmas …)` list carries `want`.
  result = false
  if pragmas.kind != TagLit: return
  var p = pragmas
  p.into:
    while p.hasMore:
      if p.kind == TagLit and p.pragmaKind == want: result = true
      skip p

proc hasPragma(decl: Cursor; want: LengPragma): bool =
  ## True when the proc's `(pragmas …)` list carries `want`.
  result = false
  var d = decl
  d.into:
    inc d                                      # name
    skip d                                     # params
    skip d                                     # result type
    if d.kind == TagLit: result = hasPragmaIn(d, want)
    while d.hasMore: skip d

proc procBody(decl: Cursor): Cursor =
  ## BODY of `(proc :name PARAMS RESULT PRAGMAS BODY)` — the last child, which
  ## is robust to wherever `parsePragmas` leaves its cursor.
  var d = decl
  d.into:
    while d.hasMore:
      result = d
      skip d


proc hasBody(decl: Cursor): bool =
  ## A bodyless `importc` declaration is a signature only: its body is `(stmts .)`
  ## or absent, so nothing but DotTokens is there.
  let b = procBody(decl)
  if b.kind != TagLit: return false
  var t = b
  result = false
  t.into:
    while t.hasMore:
      if t.kind != DotToken: result = true
      skip t

proc emitFunc(g: var WebGen; name: SymId; params: openArray[(SymId, WidthCode)];
              hasRet: bool; ret: WidthCode; locals: openArray[(SymId, WidthCode)]) =
  ## `(func NAME PARAMS RET LOCALS BODY*)` into the program: the header from the
  ## arguments, the body from `g.outp`, which is then reset for the next one.
  g.top.openTree Func
  g.top.symDef name
  g.top.openTree Params
  for (n, w) in params: g.top.param(n, w)
  g.top.closeTag
  if hasRet: g.top.width ret else: g.top.addDotToken
  g.top.openTree Locals
  for (n, w) in locals: g.top.param(n, w)
  g.top.closeTag
  g.top.addBufferSamePool g.outp
  g.top.closeTag
  g.outp = createTokenBuf(sharedPool = g.top.pool, sharedTags = g.top.tags)

proc lowerProc(g: var WebGen; sym: SymId; decl: Cursor) =
  if g.emitted.containsOrIncl(sym): return
  if hasPragma(decl, AssemblerP):
    # `{.assembler.}` promises a body that maps one-to-one onto machine
    # instructions in source order. No web target answers that promise, and
    # lowering the body as ordinary code would silently change what the
    # program does.
    err g, "`{.assembler.}` proc `" & poolSym(g.lengPool, sym) & "` has no web lowering"
  if hasPragma(decl, NakedP):
    # `{.naked.}` promises the raw register ABI of a machine function. The web
    # targets have no registers to promise, and inventing a calling convention
    # for it is exactly the plausible-but-wrong lowering this generator refuses.
    err g, "`{.naked.}` proc `" & poolSym(g.lengPool, sym) &
          "` has no web calling convention"
  g.p = ProcCtx(irName: irName(g, sym),
                symType: initTable[string, Cursor](),
                locals: initTable[string, LocalSlot]())
  let body = procBody(decl)
  var importcN, exportcN = ""
  var params: seq[(string, Cursor)]
  var t = decl
  t.into:
    inc t                                      # the name
    t.into:                                    # params
      while t.hasMore:
        var pname = ""
        var ptyp: Cursor
        var q = t
        q.into:
          pname = symName(q)
          inc q
          if hasPragmaIn(q, RegisterP):
            # A pinned register is an x86 calling-convention assertion; the
            # answer to it is a machine register, not a function parameter.
            err g, "`{.register.}` parameter `" & pname & "` in `" &
                  poolSym(g.lengPool, sym) & "`"
          skip q                               # pragmas
          ptyp = q
          while q.hasMore: skip q
        g.p.symType[pname] = ptyp
        params.add (pname, ptyp)
        skip t
    g.p.retType = t
    skip t
    parsePragmas(t, importcN, exportcN)
    while t.hasMore: skip t

  # An aggregate result is returned through a slot the caller reserves, so the
  # signature gains a hidden first parameter for it.
  g.p.sret = not g.p.retType.cursorIsNil and isAggType(g, g.p.retType)
  var taken: HashSet[string]
  if body.kind == TagLit: markTaken(body, taken)
  planFrame(g, body, params, taken)

  var sigParams: seq[(SymId, WidthCode)] = @[]
  if g.p.sret:
    g.p.sretName = tmpName(g)
    sigParams.add (g.p.sretName, wU32)
  for (pn, pt) in params: sigParams.add (irName(g, pn), paramWidth(g, pt))

  if g.p.frameSize > 0:
    g.p.fp = newTemp(g, wU32)
    g.outp.tree ExprStmt:
      g.setLocal g.p.fp:
        g.outp.tree Frame:
          g.outp.numLit int64(g.p.frameSize)
    # A scalar parameter whose address is taken arrives in a local, which
    # nothing can point at: it is spilled into the slot `addr` answers with.
    for (pn, pt) in params:
      let sl = g.p.locals[pn]
      if sl.kind == lkSlot:
        g.outp.tree ExprStmt:
          g.outp.tree HStore:
            g.outp.width widthOf(scalOf(g, pt))
            slotAddr(g, sl.off)
            g.outp.symUse irName(g, pn)

  if body.kind == TagLit:
    var b = body
    while b.hasMore: genStmt(g, b)
  leaveFrame(g)
  if g.p.sret:
    # Reached only by a body that falls off its end without a `ret`; the slot
    # is still the answer, whatever it holds.
    g.outp.tree Return: g.outp.symUse g.p.sretName

  # Every local is declared at function scope and starts at zero: a `(lab)`/
  # `jmp` pair wraps a statement list in a label block, and a local declared
  # inside it would be out of sight the moment the `break` lands.
  var locals: seq[(SymId, WidthCode)] = @[]
  for nm in g.p.regLocals:
    locals.add (irName(g, nm), widthOf(scalOf(g, g.p.symType[nm])))
  for tv in g.p.temps: locals.add tv
  var hasRet = false
  let rw = resultWidth(g, g.p.retType, hasRet)
  emitFunc(g, g.p.irName, sigParams, hasRet, rw, locals)

proc isHostDeclaration(decl: Cursor): bool =
  ## An `importc`/`importcpp`/`importjs` proc is a SIGNATURE only: the host
  ## implements it. A proc with an empty body and no import pragma is a
  ## DEFINITION that does nothing, and it must still be emitted — a call to it
  ## is a call to that empty function, not to the host.
  hasPragma(decl, ImportcP) or hasPragma(decl, ImportcppP) or hasPragma(decl, ImportjsP)

proc ensureProc(g: var WebGen; sym: SymId; decl: Cursor) =
  ## Schedule a proc for lowering. An `importc` declaration with no body is not
  ## a definition — the host implements it — so it is never lowered, and a call
  ## to it is refused at the call site (M7 binds those through the bridge).
  if g.emitted.contains(sym): return
  for s in g.pending:
    if s[0] == sym: return
  if hasBody(decl) or not isHostDeclaration(decl): g.pending.add (sym, decl)

proc genMemcmpFunc(g: var WebGen) =
  ## C's `memcmp` as an ordinary IR function — neither target has a machine
  ## form for it: the difference of the first differing UNSIGNED byte pair,
  ## 0 when the first `n` bytes match.
  let a = g.irPool.syms.getOrIncl "a"
  let b = g.irPool.syms.getOrIncl "b"
  let n = g.irPool.syms.getOrIncl "n"
  let x = g.irPool.syms.getOrIncl "x"
  let y = g.irPool.syms.getOrIncl "y"
  template bump(v: SymId; w: WidthCode; op: WebTag) =
    g.outp.tree ExprStmt:
      g.setLocal v:
        g.outp.tree op:
          g.outp.width w
          g.outp.symUse v
          g.outp.numLit 1
  g.outp.tree While:
    g.outp.tree Neq:
      g.outp.width wI32
      g.outp.symUse n
      g.outp.numLit 0
    g.outp.tree ExprStmt:
      g.setLocal x: g.hloadOf(wU8, a)
    g.outp.tree ExprStmt:
      g.setLocal y: g.hloadOf(wU8, b)
    g.outp.tree If:
      g.outp.tree Neq:
        g.outp.width wI32
        g.outp.symUse x
        g.outp.symUse y
      g.outp.tree Return:
        g.outp.tree Sub:
          g.outp.width wI32
          g.outp.symUse x
          g.outp.symUse y
    bump(a, wU32, Add)
    bump(b, wU32, Add)
    bump(n, wI32, Sub)
  g.outp.tree Return: g.outp.numLit 0
  emitFunc(g, g.memcmpFn, [(a, wU32), (b, wU32), (n, wI32)], true, wI32,
           [(x, wI32), (y, wI32)])

proc lowerThunk(g: var WebGen; thunk, sym: SymId; decl: Cursor) =
  ## A capture-free proc stored in a CLOSURE slot: the closure proctype carries
  ## a trailing env parameter the proc itself lacks. A C ABI shrugs the extra
  ## argument off; wasm's `call_indirect` checks the signature and traps. The
  ## slot therefore holds this bridge, which has the closure's signature, drops
  ## the env and calls the real proc.
  let sig = declSignature(g, decl)
  var ps: seq[(SymId, WidthCode)] = @[]
  for i, w in sig.params: ps.add (g.irPool.syms.getOrIncl("p" & $i), w)
  ps.add (g.irPool.syms.getOrIncl("env"), wU32)
  if sig.hasRet: g.outp.openTree Return
  else: g.outp.openTree ExprStmt
  g.outp.openTree Call
  g.outp.symUse irName(g, sym)
  for i in 0 ..< sig.params.len: g.outp.symUse g.irPool.syms.getOrIncl("p" & $i)
  g.outp.closeTag
  g.outp.closeTag
  g.emitted.incl thunk
  emitFunc(g, irName(g, thunk), ps, sig.hasRet, sig.ret, [])

proc generate*(buf: var TokenBuf; inputPath: string; tags: TagPool;
               target: WebTarget; module: var WebModule;
               hostImports = false): TokenBuf =
  ## The whole program as web IR (the returned `(top …)` tree) plus the facts
  ## both renderers need besides code (`module`).
  var g = createWebGen(buf, inputPath, tags, target, hostImports)
  layoutProgram(g)
  var entryDecl: Cursor
  var haveEntry = false
  for pi in g.prog.procs:
    if pi.isEntry:
      var nc = pi.decl
      inc nc
      g.entrySym = symId(nc)
      entryDecl = pi.decl
      haveEntry = true
      break
  if not haveEntry: err g, "no entry proc (exportc \"main\") in " & inputPath
  g.top.openTree Top
  ensureProc(g, g.entrySym, entryDecl)
  # Every other exportc proc in the entry module is an external entry point: a
  # reachability root (so DCE keeps it) and an export the host calls. A
  # host-driven module (the sumi engine frame, the ward brain) exposes its
  # whole surface this way; without this rooting the procs are dead code.
  var exportRoots: seq[(SymId, string)] = @[]   # (decl symbol, C name)
  for pi in g.prog.procs:
    if pi.isEntry: continue
    var nc = pi.decl
    inc nc                                       # (proc → name
    if nc.kind != SymbolDef: continue
    let sym = symId(nc)
    var d = pi.decl
    var importcN, exportcN = ""
    d.into:
      inc d                                      # name
      skip d                                     # params
      skip d                                     # return type
      parsePragmas(d, importcN, exportcN)
      while d.hasMore: skip d
    if exportcN.len > 0 and importcN.len == 0:
      exportRoots.add (sym, exportcN)
      ensureProc(g, sym, pi.decl)
  # Lowering and static serialization feed each other across module
  # boundaries: a body addresses a foreign global whose initializer names a
  # proc nobody has reached yet. Run both to the fixpoint.
  var i = 0
  var th = 0
  while true:
    while i < g.pending.len or th < g.thunks.len:
      if i < g.pending.len:
        let (sym, decl) = g.pending[i]
        inc i
        lowerProc(g, sym, decl)
      else:
        let (thunk, sym, decl) = g.thunks[th]
        inc th
        lowerThunk(g, thunk, sym, decl)
    serializeStatics(g)
    if i >= g.pending.len and th >= g.thunks.len: break
  if g.needMemcmp: genMemcmpFunc(g)
  g.top.closeTag
  checkSegments(g)

  # The function table: slot → the IR name bound there. A slot taken for a
  # proc that was never lowered — a bodyless `importc` used as a value — is a
  # host import in host-imports mode and unbound (a trap when called) otherwise.
  var table = @[""]   # the module's names are TEXT: a renderer prints them
  for slot in 1 ..< g.tableEntries.len:
    let sym = g.tableEntries[slot]
    if sym != SymId(0) and g.emitted.contains(sym):
      table.add poolSym(g.irPool, irName(g, sym))
    elif sym != SymId(0) and g.hostImports:
      var found = false
      let decl = procDeclOf(g, sym, found)
      table.add(if found and isHostDeclaration(decl) and not hasBody(decl):
                  poolSym(g.irPool, hostImport(g, sym, decl))
                else: "")
    else:
      table.add ""
  let esig = declSignature(g, entryDecl)
  module = WebModule(imports: g.imports,
                     globals: @[(GlobErrv, wI32), (GlobOvf, wI32)],
                     dataSegs: g.dataSegs, memTop: g.memTop, table: table,
                     entry: poolSym(g.irPool, irName(g, g.entrySym)),
                     entryParams: esig.params, entryHasRet: esig.hasRet,
                     entryRet: esig.ret, callbacks: g.callbacks)
  for (sym, cName) in exportRoots:
    if g.emitted.contains(sym):
      module.exports.add (cName, poolSym(g.irPool, irName(g, sym)))
  result = move g.top
