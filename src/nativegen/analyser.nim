#
#
#           NIFC Compiler
#        (c) Copyright 2024 Andreas Rumpf
#
#    See the file "license.txt", included in this
#    distribution, for details about the copyright.
#

## Collect useful information for a native code generator.

import std / [assertions, syncio, tables, sets, intsets, strutils]

import bitabs, nifstreams, nifcursors

import ".." / nj / [model, kinds]

import slots

## Records how often every local variable is used
## and whether its address has been taken.

type
  VarInfo* = object
    defs*, usages*: int # how often the variable is defined&used.
    weight*: int # similar to `usages` but takes into consideration
                 # whether the variable is used within a loop.
    props*: set[VarProp]

  ProcBodyProps* = object
    vars*: Table[SymId, VarInfo]
    inlineStructs*: bool # candidate for struct inlining (aka scalar replacement)
    hasCall*: bool

  BasicBlock = object
    vars: seq[SymId]
    hasCall: bool

  Context = object
    inLoops, inAddr, inAsgnTarget, inArrayIndex: int
    res: ProcBodyProps
    blocks: seq[BasicBlock]

proc openBlock(c: var Context) =
  c.blocks.add BasicBlock()

proc closeBlock(c: var Context) =
  let finished = c.blocks.pop()
  if not finished.hasCall:
    for v in finished.vars:
      c.res.vars[v].props.incl AllRegs
  else:
    assert c.blocks.len > 0
    # a scope has a call if some inner scope has a call:
    c.blocks[^1].hasCall = true

const
  LoopWeight = 3 # assume that the usual loop runs 3 times. This is used
                 # to make the register allocator keep variables that are
                 # used in loops more important.

proc analyseVarUsages(c: var Context; n: var Cursor) =
  # Step 1. Analyse variable usages.
  case n.kind
  of Symbol:
    let vn = n.symId
    if c.res.vars.hasKey(vn):
      let entry = addr(c.res.vars[vn])
      if c.inAsgnTarget > 0:
        inc entry.defs
      else:
        inc entry.usages
      inc entry.weight, c.inLoops*LoopWeight
      if (c.inAddr + c.inArrayIndex) > 0:
        # arrays on the stack cannot be in registers either as registers
        # cannot be aliased!
        entry.props.incl AddrTaken

  of UnknownToken, EofToken,
     DotToken, Ident, SymbolDef,
     StringLit, CharLit, IntLit, UIntLit, FloatLit:
    inc n
  else:
    case n.stmtKind
    of NoStmt:
      let k = n.exprKind
      case k
      of AtX, PatX:
        inc n
        if k == AtX: inc c.inArrayIndex
        analyseVarUsages(c, n)
        if k == AtX: dec c.inArrayIndex
        # don't pessimize array indexes:
        let oldAddr = c.inAddr
        let oldTarget = c.inAsgnTarget
        c.inAddr = 0
        c.inAsgnTarget = 0
        analyseVarUsages(c, n)
        c.inAddr = oldAddr
        c.inAsgnTarget = oldTarget
        skipParRi n
      of DerefX:
        inc n
        let oldTarget = c.inAsgnTarget
        c.inAsgnTarget = 0
        analyseVarUsages(c, n)
        c.inAsgnTarget = oldTarget
        skipParRi n
      of AddrX:
        inc n
        inc c.inAddr
        analyseVarUsages(c, n)
        dec c.inAddr
        skipParRi n
      of DotX:
        inc n
        let inStackFrame = n.exprKind != DerefX
        if inStackFrame: inc c.inArrayIndex
        analyseVarUsages(c, n)
        if inStackFrame: dec c.inArrayIndex
        skipParRi n
      of NoExpr, NilX, InfX, NeginfX, NanX, FalseX, TrueX, SizeofX, AlignofX,
         OffsetofX:
        skip n
      of ParX, NotX, NegX, OconstrX, AconstrX, OvfX,
         AddX, SubX, MulX, DivX, ModX, ShrX, ShlX, BitandX, BitorX, BitxorX, BitnotX,
         EqX, NeqX, LeX, LtX, CastX, ConvX, BaseobjX, VX, AshrX:
        inc n
        while n.kind != ParRi:
          analyseVarUsages(c, n)
        inc n
    of StmtsS:
      while n.kind != ParRi:
        analyseVarUsages(c, n)
      inc n
    of CallS:
      inc n
      while n.kind != ParRi:
        analyseVarUsages(c, n)
      inc n
      c.blocks[^1].hasCall = true
    of VarS, GvarS, TvarS, ConstS, ResultS:
      let v = takeVarDecl(n)
      assert v.name.kind == SymbolDef
      let vn = v.name.symId
      let hasValue = v.value.kind != DotToken
      c.res.vars[vn] = VarInfo(defs: ord(hasValue))
      c.blocks[^1].vars.add vn
      if hasValue:
        var n = v.value
        analyseVarUsages(c, n)
    of KillS:
      inc n
      while n.kind != ParRi:
        assert n.kind == Symbol
        let vn = n.symId
        if not c.res.vars.hasKey(vn):
          bug "undeclared variable killed: " & pool.syms[vn]
        else:
          c.res.vars.del vn
        inc n
      inc n
    of CfvarS:
      inc n
      assert n.kind == SymbolDef
      let vn = n.symId
      inc n
      c.res.vars[vn] = VarInfo()
      c.blocks[^1].vars.add vn
      skipParRi n
    of StoreS:
      inc n
      analyseVarUsages(c, n)
      inc c.inAsgnTarget
      analyseVarUsages(c, n)
      dec c.inAsgnTarget
      skipParRi n
    of KeepovfS:
      inc n
      analyseVarUsages(c, n)
      inc c.inAsgnTarget
      analyseVarUsages(c, n)
      dec c.inAsgnTarget
      skipParRi n
    of JtrueS:
      inc n
      inc c.inAsgnTarget
      while n.kind != ParRi:
        analyseVarUsages(c, n)
      inc n
      dec c.inAsgnTarget
    of ProcS, TypeS, AssumeS, AssertS, UnknownS:
      skip n
    of LoopS:
      inc n
      inc c.inLoops
      # loop init:
      openBlock c
      assert n.kind != ParRi, "loop needs init section"
      analyseVarUsages(c, n)
      assert n.kind != ParRi, "loop needs condition"
      analyseVarUsages(c, n)
      assert n.kind != ParRi, "loop needs body"
      analyseVarUsages(c, n)
      dec c.inLoops
      closeBlock c
      if n.kind != ParRi:
        # after loop statements (optionally in this position for now)
        analyseVarUsages(c, n)
      skipParRi n
    of IteS, ItecS:
      inc n
      assert n.kind != ParRi, "ite needs condition"
      analyseVarUsages(c, n) # condition
      assert n.kind != ParRi, "ite needs then branch"
      openBlock c
      analyseVarUsages(c, n) # then
      closeBlock c
      assert n.kind != ParRi, "ite needs else branch"
      openBlock c
      analyseVarUsages(c, n) # else
      closeBlock c
      if n.kind != ParRi:
        # optional join information:
        skip n
      skipParRi n
    of AsmS:
      inc n
      while n.kind != ParRi:
        analyseVarUsages(c, n)
      inc n

proc analyseVarUsages*(n: Cursor): ProcBodyProps =
  var c = Context()
  c.blocks.add BasicBlock() # there is always one basic block
  var n = n
  if n.stmtKind == ProcS:
    var prc = takeProcDecl(n)
    var params = prc.params
    if params.kind != DotToken:
      inc params
      while params.kind != ParRi:
        var p = takeParamDecl(params)
        assert p.name.kind == SymbolDef
        let vn = p.name.symId
        c.res.vars[vn] = VarInfo(defs: 1) # it is a parameter, it has a value
        c.blocks[^1].vars.add vn
    analyseVarUsages c, prc.body
  else:
    analyseVarUsages c, n
  c.res.hasCall = c.blocks[0].hasCall
  result = ensureMove(c.res)
