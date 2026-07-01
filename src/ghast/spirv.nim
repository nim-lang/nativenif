#       ghast — SPIR-V tag set for the GPU backend
# (c) Copyright 2026 Andreas Rumpf
#
# See the file "license.txt", included in this distribution.

## The SPIR-V *output buffer* is a `nifcore` `TokenBuf` whose tag namespace is
## the `SpirvOp` enum below — nifcore's "custom tag set" hook (`createTags[E]`).
## So a SPIR-V module is just NIF: every instruction is a `(OpFoo …)` tree, id
## references are `Symbol`s, literal operands are `StrLit`/`IntLit`, and — the
## NIF-idiomatic part — keyword operands (`Shader`, `Logical`, `GLSL450`, …) are
## *nullary tags* `(Shader)` `(Logical)`, exactly like NIF spells `(true)` /
## `(false)` / `(nan)`. A keyword is a `TagId`, never an `Ident`; that is why the
## operand keywords live in `SpirvOp` alongside the opcodes (one buffer, one tag
## pool). The `render` module turns that NIF back into the real textual SPIR-V
## syntax (`%id = OpFoo …`).
##
## A result-defining instruction binds its id under the synthetic `ghDef` tag —
## `(Def <SymbolDef %id> (OpFoo …))` — so the `SymbolDef` is bound by a tag (as
## NIF definitions always are) and never appears as an operand; operand positions
## carry only `Symbol` *uses*. This mirrors arkham's `(rebind <SymbolDef> …)` on
## the CPU side.
##
## Keeping SPIR-V *as NIF* (rather than emitting text directly) means the device
## IR shares the whole NIF toolchain — same buffer, same cursor walk, same
## binary/text serialisation — exactly like arkham's typed asm-NIF on the CPU
## side.

import nifcore

type
  SpirvOp* = enum
    ## Tag namespace for the SPIR-V output buffer: synthetic containers, then
    ## opcodes, then keyword operands. `createTags[SpirvOp]` registers every
    ## value as a NIF tag (its `$` is the spelling), so `tagId`/`render` map
    ## straight between an enum value and its tag.
    ##
    ## `ghModule` is a synthetic root container (a SPIR-V module is just a
    ## sequence of instructions — there is no "module" opcode); `ghDef` binds a
    ## result id to the instruction it heads. `render` treats both specially.
    ghModule = "Module"
    ghDef = "Def"
    # ── opcodes ──────────────────────────────────────────────────────────────
    OpCapability = "OpCapability"
    OpMemoryModel = "OpMemoryModel"
    OpEntryPoint = "OpEntryPoint"
    OpExecutionMode = "OpExecutionMode"
    OpDecorate = "OpDecorate"
    OpMemberDecorate = "OpMemberDecorate"
    OpTypeVoid = "OpTypeVoid"
    OpTypeBool = "OpTypeBool"
    OpTypeInt = "OpTypeInt"
    OpTypeFloat = "OpTypeFloat"
    OpTypeVector = "OpTypeVector"
    OpTypeRuntimeArray = "OpTypeRuntimeArray"
    OpTypeStruct = "OpTypeStruct"
    OpTypePointer = "OpTypePointer"
    OpTypeFunction = "OpTypeFunction"
    OpConstant = "OpConstant"
    OpFunction = "OpFunction"
    OpFunctionParameter = "OpFunctionParameter"
    OpLabel = "OpLabel"
    OpVariable = "OpVariable"
    OpLoad = "OpLoad"
    OpStore = "OpStore"
    OpAccessChain = "OpAccessChain"
    OpBitcast = "OpBitcast"
    OpSConvert = "OpSConvert"
    OpCompositeExtract = "OpCompositeExtract"
    OpIAdd = "OpIAdd"
    OpISub = "OpISub"
    OpIMul = "OpIMul"
    OpReturn = "OpReturn"
    OpReturnValue = "OpReturnValue"
    OpFunctionEnd = "OpFunctionEnd"
    # ── keyword operands — UpperCase like the opcodes, each identifier its own
    #    SPIR-V spelling (so `$` is what SPIR-V expects); emitted as a nullary tag
    #    (`enumOp`). Grouped Nim-side by SPIR-V operand category.
    Shader = "Shader"                # Capability
    Int8 = "Int8"
    Int16 = "Int16"
    Int64 = "Int64"
    Logical = "Logical"              # AddressingModel
    GLSL450 = "GLSL450"              # MemoryModel
    GLCompute = "GLCompute"          # ExecutionModel
    LocalSize = "LocalSize"          # ExecutionMode
    None = "None"                    # FunctionControl
    Function = "Function"            # StorageClass
    Input = "Input"
    StorageBuffer = "StorageBuffer"
    GlobalInvocationId = "GlobalInvocationId"   # BuiltIn
    Block = "Block"                  # Decoration
    BuiltIn = "BuiltIn"
    ArrayStride = "ArrayStride"
    Offset = "Offset"
    DescriptorSet = "DescriptorSet"
    Binding = "Binding"

template tagId*(op: SpirvOp): TagId = TagId(uint32(op) + 1'u32)

proc newSpirvModule*(): TokenBuf =
  ## A fresh output buffer whose tag pool is the `SpirvOp` enum.
  createTokenBuf(64, nil, createTags[SpirvOp]())

proc beginModule*(b: var TokenBuf) = b.openTag ghModule.tagId
proc endModule*(b: var TokenBuf) = b.closeTag()

template instr*(b: var TokenBuf; op: SpirvOp; body: untyped) =
  ## One result-less `(Op… <operands>)` instruction tree (OpStore, OpReturn,
  ## OpDecorate, …). Result-defining instructions use `def` instead.
  b.openTag op.tagId
  body
  b.closeTag()

template def*(b: var TokenBuf; id: SymId; op: SpirvOp; body: untyped) =
  ## A result-defining instruction: `(Def <SymbolDef id> (Op… <operands>))`.
  ## The id is bound by the `ghDef` tag — a NIF `SymbolDef` is always *bound* by
  ## a tag, never dropped into operand position — and `body` emits only `Symbol`
  ## uses / literals. `render` turns the whole tree into `%id = Op… …`.
  b.openTag ghDef.tagId
  b.add symdefToken(id)
  b.openTag op.tagId
  body
  b.closeTag()
  b.closeTag()

# Operand emitters — thin, type-checked wrappers over the raw buffer verbs so
# the codegen reads in SPIR-V terms (an `id` use is a symbol, a keyword is a tag).
const idSuffix* = ".0"
  ## The module suffix every SPIR-V id carries. NIF text classifies a bare token
  ## as a `Symbol` only when it has a `.`-suffix (otherwise it re-parses as an
  ## `Ident`); the suffix makes ids serialise and round-trip as real symbols (the
  ## same `name.<n>` convention arkham uses on the CPU side). The codegen mints
  ## each id string already dotted (e.g. `int64.0`) and interns it into the pool
  ## as a `SymId`, which `def`/`idRef` emit; `render` strips the suffix for
  ## display (`int64.0` -> `%int64`).
proc idRef*(b: var TokenBuf; id: SymId) = b.add symToken(id)
proc enumOp*(b: var TokenBuf; op: SpirvOp) =
  ## A keyword operand: the nullary tag `(Shader)` / `(Logical)` / … — in NIF a
  ## keyword IS a tag, exactly like `(true)` / `(false)`, never an `Ident`.
  b.openTag op.tagId
  b.closeTag()
proc strOp*(b: var TokenBuf; s: string) = b.addStrLit s
proc litOp*(b: var TokenBuf; v: int64) = b.addIntLit v
