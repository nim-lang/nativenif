#       ghast — SPIR-V tag set for the GPU backend
# (c) Copyright 2026 Andreas Rumpf
#
# See the file "license.txt", included in this distribution.

## The SPIR-V *output buffer* is a `nifcore` `TokenBuf` whose tag namespace is
## the `SpirvOp` enum below — nifcore's "custom tag set" hook (`createTags[E]`).
## So a SPIR-V module is just NIF: every instruction is a `(OpFoo …)` tree, with
## result ids as `SymbolDef`s, id references as `Symbol`s, enum operands as
## `Ident`s and literal operands as `StrLit`/`IntLit`. The `render` module turns
## that NIF back into the real textual SPIR-V syntax (`%id = OpFoo …`).
##
## Keeping SPIR-V *as NIF* (rather than emitting text directly) means the device
## IR shares the whole NIF toolchain — same buffer, same cursor walk, same
## binary/text serialisation — exactly like arkham's typed asm-NIF on the CPU
## side. Sibling operand enums (`Capability`, `MemoryModel`, …) name-check the
## enum operands; their `$` is the spelling SPIR-V expects.

import nifcore

type
  SpirvOp* = enum
    ## Tag namespace for the SPIR-V output buffer. Each value's `$` is the real
    ## opcode spelling, so `createTags[SpirvOp]` registers them as NIF tags and
    ## `render` maps a tag straight back to `Op…` syntax. `ghModule` is a
    ## synthetic root container (there is no SPIR-V "module" instruction — a
    ## module is just a sequence of instructions); `render` treats it specially.
    ghModule = "Module"
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

  # Operand enums — their `$` is the spelling SPIR-V expects, emitted as Idents.
  Capability* = enum
    capShader = "Shader"
  AddressingModel* = enum
    addrLogical = "Logical"
  MemoryModel* = enum
    memGLSL450 = "GLSL450"
  ExecutionModel* = enum
    exeGLCompute = "GLCompute"
  ExecutionMode* = enum
    modeLocalSize = "LocalSize"
  FunctionControl* = enum
    fcNone = "None"
  StorageClass* = enum
    scFunction = "Function"
    scInput = "Input"
    scStorageBuffer = "StorageBuffer"
  BuiltIn* = enum
    biGlobalInvocationId = "GlobalInvocationId"
  Decoration* = enum
    decBlock = "Block"
    decBuiltIn = "BuiltIn"
    decArrayStride = "ArrayStride"
    decOffset = "Offset"
    decDescriptorSet = "DescriptorSet"
    decBinding = "Binding"

template tagId*(op: SpirvOp): TagId = TagId(uint32(op) + 1'u32)

proc newSpirvModule*(): TokenBuf =
  ## A fresh output buffer whose tag pool is the `SpirvOp` enum.
  createTokenBuf(64, nil, createTags[SpirvOp]())

proc beginModule*(b: var TokenBuf) = b.openTag ghModule.tagId
proc endModule*(b: var TokenBuf) = b.closeTag()

template instr*(b: var TokenBuf; op: SpirvOp; body: untyped) =
  ## One `(Op… <operands>)` instruction tree.
  b.openTag op.tagId
  body
  b.closeTag()

# Operand emitters — thin, type-checked wrappers over the raw buffer verbs so
# the codegen reads in SPIR-V terms (an `id` is a symbol, an enum is an ident).
const idSuffix* = ".0"
  ## The module suffix every SPIR-V id must carry. NIF text classifies a bare
  ## token as a `Symbol` only when it has a `.`-suffix (otherwise it re-parses as
  ## an `Ident`); the suffix makes ids serialise and round-trip as real symbols.
  ## Ids are passed to `resultId`/`idRef` **verbatim** (the codegen mints them
  ## already dotted, e.g. `int64.0`); `render` strips the suffix for display
  ## (`int64.0` -> `%int64`).
proc resultId*(b: var TokenBuf; id: string) = b.addSymDef id
proc idRef*(b: var TokenBuf; id: string) = b.addSymUse id
proc enumOp*[E: enum](b: var TokenBuf; e: E) = b.addIdent $e
proc identOp*(b: var TokenBuf; s: string) = b.addIdent s
proc strOp*(b: var TokenBuf; s: string) = b.addStrLit s
proc litOp*(b: var TokenBuf; v: int64) = b.addIntLit v
