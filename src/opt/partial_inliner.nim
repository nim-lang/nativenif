#
#
#           Partial Inliner
#        (c) Copyright 2025 Andreas Rumpf
#
#    See the file "license.txt", included in this
#    distribution, for details about the copyright.
#

## Inliner. We inline function calls that are annotated with `.inline` or match
## weight-based heuristics.
##
## Inlining requires:
## - copy the body of the function to the caller into a new block `B`.
## - replace the parameter by a local variable that is initialized with the
##   passed value.
## - replace `result` by the assigned destination of `x = toInline(args)` if it exists,
##   otherwise by a temporary variable.
## - replace `return` by `break B`.
## - copy local variables from the body into fresh ones.
##
## Weight-based inlining heuristic:
## Each function has a weight vector `[w₀, w₁, w₂, ...]` where each weight
## corresponds to an argument position. At a callsite, if argument `i` is a constant
## (literal value), weight `wᵢ` is added to a sum.
##
## Inlining modes:
## - `sum >= 1.0`: Full inlining (entire function body)
## - `0.3 <= sum < 1.0`: Partial inlining (guard/early return checks only)
## - `sum < 0.3`: No inlining
##
## Partial inlining is useful for functions with guard patterns at entry.
## In NJVL format (after return elimination), guards appear as entry-level `ite` statements
## with the bulk of the function in the `else` branch:
## ```
## (stmts
##   (cfvar ret = false)
##   (ite
##     condition        # Guard check
##     (stmts guard-code)
##     (stmts ... bulk of function ...))
## )
## ```
## When called with constant arguments, guard conditions can be evaluated at compile-time,
## moving checks to the callsite while avoiding inlining the entire function body.
##
## Weight vectors are automatically computed by analyzing the function body:
## - Parameters used in conditions (if/while/case): high weight (0.5 per use)
## - Parameters used in comparisons: high weight (0.3 per use)
## - Parameters used in array indexing: high weight (0.4 per use)
## - Parameters used in arithmetic: medium weight (0.2 per use)
## - Parameters passed to functions: low weight (0.1 per use)
##
## Weights can also be manually set via `setInlineWeights()` to override automatic computation.

import std / [tables, assertions, sequtils]
include nifprelude
import ".." / lib / symparser
import ".." / nimony / [nimony_model, decls, programs, typenav, sizeof, expreval]
import ".." / njvl / njvl_model
import duplifier

type
  TargetKind = enum
    TargetIsNone, TargetIsSym, TargetIsNode
  Target = object
    kind: TargetKind
    sym: SymId
    pos: Cursor

  Context* = object
    thisRoutine: SymId
    thisModuleSuffix: string
    globals, locals: Table[string, int]
    typeCache: TypeCache
    ptrSize: int
    # Weight vectors for inlining heuristics: maps function symbol -> weight vector
    # Each weight corresponds to an argument position. If sum(weights for constant args) >= 1.0, inline.
    inlineWeights: Table[SymId, seq[float]]

  VarReplacement = object
    needsDeref: bool
    sym: SymId

  InlineContext* = object
    returnLabel: SymId
    resultSym: SymId
    newVars: Table[SymId, VarReplacement]
    target: Target
    c: ptr Context

proc createInliner(thisModuleSuffix: string; ptrSize: int): Context =
  result = Context(thisRoutine: NoSymId, thisModuleSuffix: thisModuleSuffix,
    typeCache: createTypeCache(), ptrSize: ptrSize,
    inlineWeights: initTable[SymId, seq[float]]())

when not defined(nimony):
  proc tr(c: var Context; dest: var TokenBuf; n: var Cursor)

proc trProcDecl(c: var Context; dest: var TokenBuf; n: var Cursor) =
  let decl = n
  c.typeCache.openScope()
  dest.add n
  var r = takeRoutine(n, SkipExclBody)
  let oldThisRoutine = c.thisRoutine
  c.thisRoutine = r.name.symId
  copyTree dest, r.name
  copyTree dest, r.exported
  copyTree dest, r.pattern
  copyTree dest, r.typevars
  copyTree dest, r.params
  c.typeCache.registerParams(r.name.symId, decl, r.params)
  copyTree dest, r.pragmas
  copyTree dest, r.effects
  skip n # effects
  if n.stmtKind == StmtsS and not isGeneric(r):
    tr c, dest, n
  else:
    takeTree dest, n
  dest.takeParRi(n)
  c.thisRoutine = oldThisRoutine
  c.typeCache.closeScope()

proc shouldInlineRoutine(pragmas: Cursor): bool =
  hasPragma(pragmas, InlineP)

proc isConstantArg(arg: Cursor): bool =
  ## Check if an argument expression is a compile-time constant.
  ## This includes literals and compile-time evaluable expressions.
  case arg.kind
  of IntLit, UIntLit, FloatLit, StringLit, CharLit:
    result = true
  of ParLe:
    # Check for boolean constants and other compile-time expressions
    result = arg.exprKind in {TrueX, FalseX}
  else:
    result = false

proc countParams(params: Cursor): int =
  ## Count the number of parameters in a routine's params cursor.
  ## Skips compile-time only parameters (typedesc, static).
  result = 0
  if params.kind == DotToken:
    return
  if params.kind == ParLe and params.substructureKind == ParamsU:
    var p = params
    inc p  # skip opening paren
    while p.kind != ParRi:
      if p.symKind == ParamY:
        let param = asLocal(p)
        if not isCompileTimeType(param.typ):
          inc result
        # Skip this parameter
        skip p
      else:
        inc p  # might be something else, just skip

type
  ParamUsage = object
    inConditions: int      # Used in if/while/case conditions
    inArithmetic: int      # Used in arithmetic operations
    inComparisons: int     # Used in comparisons
    inIndexing: int        # Used in array indexing
    inCalls: int           # Passed as argument to other functions
    inAssignments: int     # Used in assignments (lower weight)

proc computeWeightVector(c: var Context; routine: Routine): seq[float] =
  ## Analyze the routine body to compute weight vector based on parameter usage.
  ## Returns empty seq if analysis fails or routine has no body.
  result = @[]

  if routine.body.kind == DotToken:
    return  # No body to analyze

  # Build map from parameter symbol to runtime parameter index
  var paramIndexMap: Table[SymId, int] = initTable[SymId, int]()
  var runtimeParamCount = 0

  if routine.params.kind != DotToken and routine.params.kind == ParLe and
     routine.params.substructureKind == ParamsU:
    var p = routine.params
    inc p  # skip (params
    while p.kind != ParRi:
      if p.symKind == ParamY:
        let param = asLocal(p)
        skip p
        if not isCompileTimeType(param.typ):
          paramIndexMap[param.name.symId] = runtimeParamCount
          inc runtimeParamCount
      else:
        inc p

  if runtimeParamCount == 0:
    return

  # Initialize usage tracking
  var usage: seq[ParamUsage] = newSeq[ParamUsage](runtimeParamCount)
  for i in 0..<runtimeParamCount:
    usage[i] = ParamUsage()

  # Track context as we traverse
  var inCondition = false
  var inComparison = false

  proc analyzeExpr(n: var Cursor) =
    var nested = 0
    while true:
      case n.kind
      of Symbol:
        let symId = n.symId
        if symId in paramIndexMap:
          let idx = paramIndexMap[symId]
          if inCondition:
            usage[idx].inConditions += 1
          elif inComparison:
            usage[idx].inComparisons += 1
          else:
            # Default: assume arithmetic or general use
            usage[idx].inArithmetic += 1
        inc n
      of SymbolDef, Ident, IntLit, UIntLit, FloatLit, StringLit, CharLit,
         UnknownToken, DotToken, EofToken:
        inc n
      of ParRi:
        if nested > 0:
          dec nested
          inc n
        else:
          break
      of ParLe:
        case n.exprKind
        of IfX, WhileX, CaseX:
          inCondition = true
          inc n
          # Analyze condition
          if n.kind != ParRi:
            analyzeExpr(n)
          inCondition = false
          inc nested
          inc n
        of EqX, NeX, LtX, LeX, GtX, GeX:
          inComparison = true
          inc n
          while n.kind != ParRi:
            analyzeExpr(n)
          inComparison = false
          inc nested
          inc n
        of AddX, SubX, MulX, DivX, ModX, ShlX, ShrX, AndX, OrX, XorX:
          inc n
          while n.kind != ParRi:
            analyzeExpr(n)
          inc nested
          inc n
        of ArrayAccX:
          inc n
          # First child is array, second is index
          var childIdx = 0
          while n.kind != ParRi:
            if childIdx == 1:
              # This is the index - track indexing usage for params
              var savedCond = inCondition
              var savedComp = inComparison
              inCondition = false
              inComparison = false
              # Check if this expression is a parameter symbol
              var idxExpr = n
              var isParam = false
              var paramIdx = -1
              if idxExpr.kind == Symbol:
                let symId = idxExpr.symId
                if symId in paramIndexMap:
                  paramIdx = paramIndexMap[symId]
                  isParam = true

              analyzeExpr(n)

              # Mark as indexing usage if it's a parameter
              if isParam and paramIdx >= 0:
                usage[paramIdx].inIndexing += 1

              inCondition = savedCond
              inComparison = savedComp
            else:
              analyzeExpr(n)
            inc childIdx
          inc nested
          inc n
        of CallKinds:
          inc n
          # First child is callee, rest are arguments
          var argIdx = 0
          while n.kind != ParRi:
            if argIdx > 0:
              # This is an argument - track call usage for params
              var savedCond = inCondition
              var savedComp = inComparison
              inCondition = false
              inComparison = false

              # Check if this expression is a parameter symbol
              var argExpr = n
              var isParam = false
              var paramIdx = -1
              if argExpr.kind == Symbol:
                let symId = argExpr.symId
                if symId in paramIndexMap:
                  paramIdx = paramIndexMap[symId]
                  isParam = true

              analyzeExpr(n)

              # Mark as call usage if it's a parameter
              if isParam and paramIdx >= 0:
                usage[paramIdx].inCalls += 1

              inCondition = savedCond
              inComparison = savedComp
            else:
              analyzeExpr(n)
            inc argIdx
          inc nested
          inc n
        of AsgnX:
          inc n
          # First child is target, second is value
          var childIdx = 0
          while n.kind != ParRi:
            if childIdx == 1:
              # This is the value being assigned - mark as assignment usage
              var savedCond = inCondition
              var savedComp = inComparison
              inCondition = false
              inComparison = false
              analyzeExpr(n)
              inCondition = savedCond
              inComparison = savedComp
            else:
              analyzeExpr(n)
            inc childIdx
          inc nested
          inc n
        else:
          inc nested
          inc n
      if nested == 0 and n.kind != ParRi:
        break

  proc analyzeStmt(n: var Cursor) =
    case n.stmtKind
    of StmtsS:
      inc n  # skip (stmts
      while n.kind != ParRi:
        analyzeStmt(n)
      inc n  # skip )
    of IfS:
      inc n  # skip (if
      inCondition = true
      analyzeExpr(n)  # condition
      inCondition = false
      # then branch
      if n.kind != ParRi:
        analyzeStmt(n)
      # else branch
      if n.kind != ParRi:
        analyzeStmt(n)
      if n.kind == ParRi:
        inc n
    of WhileS:
      inc n  # skip (while
      inCondition = true
      analyzeExpr(n)  # condition
      inCondition = false
      # body
      if n.kind != ParRi:
        analyzeStmt(n)
      if n.kind == ParRi:
        inc n
    of CaseS:
      inc n  # skip (case
      inCondition = true
      analyzeExpr(n)  # selector
      inCondition = false
      # branches
      while n.kind != ParRi:
        analyzeStmt(n)
      if n.kind == ParRi:
        inc n
    of AsgnS:
      inc n  # skip (asgn
      analyzeExpr(n)  # left side
      analyzeExpr(n)  # right side
      if n.kind == ParRi:
        inc n
    of CallS:
      analyzeExpr(n)  # analyze as expression
    of RetS:
      inc n  # skip (ret
      if n.kind != DotToken and n.kind != ParRi:
        analyzeExpr(n)
      if n.kind == ParRi:
        inc n
    of VarS, LetS, ConstS, GvarS, TvarS, GletS, TletS, ResultS:
      skip n  # skip variable declarations
    of ScopeS, BlockS:
      inc n  # skip header
      while n.kind != ParRi:
        analyzeStmt(n)
      if n.kind == ParRi:
        inc n
    else:
      skip n  # skip other statements

  # Analyze the body
  if routine.body.kind == ParLe:
    var body = routine.body
    analyzeStmt(body)

  # Compute weights from usage patterns
  # Higher weights for uses that benefit most from constant propagation
  result = newSeq[float](runtimeParamCount)
  for i in 0..<runtimeParamCount:
    var weight = 0.0
    let u = usage[i]

    # Conditions have highest weight (enables dead code elimination)
    if u.inConditions > 0:
      weight += 0.5 * min(u.inConditions.float, 2.0)  # Cap at 2 uses

    # Comparisons benefit from constant folding
    if u.inComparisons > 0:
      weight += 0.3 * min(u.inComparisons.float, 2.0)

    # Array indexing benefits from constant propagation
    if u.inIndexing > 0:
      weight += 0.4 * min(u.inIndexing.float, 2.0)

    # Arithmetic operations benefit moderately
    if u.inArithmetic > 0:
      weight += 0.2 * min(u.inArithmetic.float, 3.0)

    # Function calls have lower benefit
    if u.inCalls > 0:
      weight += 0.1 * min(u.inCalls.float, 2.0)

    # Normalize: if total uses > 0, ensure minimum weight
    let totalUses = u.inConditions + u.inComparisons + u.inIndexing +
                    u.inArithmetic + u.inCalls + u.inAssignments
    if totalUses == 0:
      weight = 0.0
    else:
      # Ensure at least some weight if used
      weight = max(weight, 0.1)
      # Cap maximum weight
      weight = min(weight, 1.0)

    result[i] = weight

proc getWeightVector(c: var Context; routine: Routine; calleeSym: SymId): seq[float] =
  ## Get the weight vector for a routine. If not manually set, compute it from the body.
  ## The weight vector can be manually set via setInlineWeights, otherwise it's computed.
  if calleeSym in c.inlineWeights:
    result = c.inlineWeights[calleeSym]
  else:
    # Compute weights automatically from body analysis
    result = computeWeightVector(c, routine)
    # Cache the computed weights
    if result.len > 0:
      c.inlineWeights[calleeSym] = result

proc setInlineWeights*(c: var Context; sym: SymId; weights: seq[float]) =
  ## Set the inline weight vector for a function symbol.
  ## Each weight corresponds to an argument position (0-indexed).
  c.inlineWeights[sym] = weights

type
  InlineMode* = enum
    NoInline
    PartialInline    # Inline only guards/early returns
    FullInline       # Inline entire function body

  GuardBlock = object
    guardStart: Cursor  # Start of guard statements
    guardEnd: Cursor    # End of guard statements (points to next statement after guards)
    hasGuards: bool     # Whether any guards were found

proc extractGuards(body: Cursor): GuardBlock =
  ## Extract guard patterns from NJVL format.
  ## Guards are consecutive entry-level `ite` statements at the start of the function.
  ## The bulk of the function body is in the `else` branch of these guards.
  ## Pattern: (ite condition (stmts guard-code) (stmts bulk-body) ...)
  ## Returns the guard block range (the ite statements themselves).
  result = GuardBlock(hasGuards: false)

  if body.kind == DotToken or body.kind != ParLe or body.stmtKind != StmtsS:
    return

  var stmts = body
  inc stmts  # skip (stmts
  result.guardStart = stmts
  result.guardEnd = stmts
  var guardCount = 0

  # Skip initial cfvar declarations
  while result.guardEnd.kind != ParRi:
    if result.guardEnd.kind == ParLe and result.guardEnd.njvlKind == CfvarV:
      skip result.guardEnd  # skip cfvar declaration
      result.guardStart = result.guardEnd  # Update start to after cfvars
    else:
      break

  # Look for consecutive entry-level `ite` statements
  # These are guards - the bulk of the function is in their else branches
  var cursor = result.guardStart
  while cursor.kind != ParRi:
    if cursor.kind == ParLe and cursor.njvlKind == IteV:
      # This is a guard pattern - an ite at the start
      guardCount += 1
      skip cursor  # skip the entire ite statement
      result.guardEnd = cursor  # Update end to after this guard
    else:
      # Not an ite, stop looking for guards
      break

  if guardCount > 0:
    result.hasGuards = true

proc shouldInlineCall(c: var Context; n: Cursor; routine: var Routine): InlineMode =
  result = NoInline
  if n.exprKind in CallKinds and c.thisRoutine != NoSymId:
    let callee = n.firstSon
    if callee.kind == Symbol:
      let calleeSym = callee.symId
      let s = tryLoadSym(calleeSym)
      if s.status == LacksNothing:
        # who says we cannot inline recursions?
        routine = asRoutine(s.decl)
        if routine.kind in {ProcY, FuncY, ConverterY}:
          # Check explicit .inline pragma first
          if shouldInlineRoutine(routine.pragmas):
            result = FullInline
          else:
            # Check weight-based heuristic
            let weights = getWeightVector(c, routine, calleeSym)
            if weights.len > 0:
              var args = n
              inc args  # skip (call
              inc args  # skip function symbol
              var weightSum = 0.0
              var params = routine.params

              # Traverse arguments and parameters in parallel
              # Skip compile-time parameters (typedesc, static) - they consume args but don't count for weights
              if params.kind != DotToken and params.kind == ParLe and params.substructureKind == ParamsU:
                var p = params
                inc p  # skip opening paren of (params
                var runtimeParamIndex = 0

                while args.kind != ParRi and p.kind != ParRi:
                  if p.symKind == ParamY:
                    let param = asLocal(p)
                    skip p  # advance past this parameter

                    if isCompileTimeType(param.typ):
                      # Skip compile-time parameter and its argument
                      skip args
                    else:
                      # This is a runtime parameter - check if we have a weight and constant arg
                      if runtimeParamIndex < weights.len:
                        let weight = weights[runtimeParamIndex]
                        if weight > 0.0 and isConstantArg(args):
                          weightSum += weight
                      inc runtimeParamIndex
                      skip args
                  else:
                    inc p  # skip non-parameter nodes in params

              # Determine inlining mode based on weight sum and guard detection
              if weightSum >= 1.0:
                result = FullInline
              elif weightSum >= 0.3:
                # Check if function has guards that could benefit from partial inlining
                let guards = extractGuards(routine.body)
                if guards.hasGuards:
                  result = PartialInline

proc makeGlobalSym*(c: var Context; result: var string) =
  var counter = addr c.globals.mgetOrPut(result, -1)
  counter[] += 1
  result.add '.'
  result.addInt counter[]
  result.add '.'
  result.add c.thisModuleSuffix

proc makeLocalSym*(c: var Context; result: var string) =
  var counter = addr c.locals.mgetOrPut(result, -1)
  counter[] += 1
  result.add '.'
  result.addInt counter[]

proc newSymId(c: var Context; s: SymId): SymId =
  var isGlobal = false
  var name = "`" & extractBasename(pool.syms[s], isGlobal)
  if isGlobal:
    c.makeGlobalSym(name)
  else:
    c.makeLocalSym(name)
  result = pool.syms.getOrIncl(name)

proc addVarReplacement(dest: var TokenBuf; v: VarReplacement; info: PackedLineInfo) =
  if v.needsDeref:
    copyIntoKind dest, DerefX, info:
      dest.addSymUse v.sym, info
  else:
    dest.addSymUse v.sym, info

proc inlineRoutineBody(c: var InlineContext; dest: var TokenBuf; n: var Cursor) =
  let info = n.info
  case n.kind
  of SymbolDef:
    let id = n.symId
    let freshId = newSymId(c.c[], id)

    c.newVars[id] = VarReplacement(sym: freshId, needsDeref: false)
    dest.addSymDef freshId, info
    inc n
  of Symbol:
    if c.resultSym == n.symId:
      case c.target.kind
      of TargetIsNone:
        let toReplace = c.newVars.getOrDefault(n.symId)
        assert toReplace.sym != NoSymId, "cannot find result declaration"
        addVarReplacement(dest, toReplace, info)
      of TargetIsSym:
        dest.addSymUse c.target.sym, info
      of TargetIsNode:
        copyTree dest, c.target.pos
    else:
      let toReplace = c.newVars.getOrDefault(n.symId)
      if toReplace.sym != NoSymId:
        addVarReplacement(dest, toReplace, info)
      else:
        dest.add n
    inc n
  of Ident, IntLit, UIntLit, FloatLit, CharLit, StringLit, UnknownToken, DotToken, EofToken:
    dest.add n
    inc n
  of ParRi:
    bug "unhandled ')' in inliner.nim"
  of ParLe:
    case n.stmtKind
    of RetS:
      let retVal = n.firstSon
      if retVal.kind != DotToken and not (retVal.kind == Symbol and c.resultSym == retVal.symId):
        # generate assignment: `dest = result`
        copyIntoKind dest, AsgnS, info:
          case c.target.kind
          of TargetIsNone:
            assert c.resultSym != NoSymId
            let toReplace = c.newVars.getOrDefault(c.resultSym)
            assert toReplace.sym != NoSymId, "cannot find result declaration"
            addVarReplacement(dest, toReplace, info)
          of TargetIsSym:
            assert c.target.sym != NoSymId
            dest.addSymUse c.target.sym, info
          of TargetIsNode:
            copyTree dest, c.target.pos
          inc n
          inlineRoutineBody c, dest, n

      copyIntoKind dest, BreakS, info:
        dest.addSymUse c.returnLabel, info
      assert n.kind == ParRi
      inc n
    of ResultS:
      if c.target.kind == TargetIsNone:
        # we need the result declaration. But it is inlined, so
        # it is not a `ResultDecl`!
        copyIntoKind dest, VarS, info:
          while n.kind != ParRi:
            inlineRoutineBody(c, dest, n)
        dest.addParRi()
        assert n.kind == ParRi
        inc n
      else:
        # discard the result declaration!
        discard
      c.resultSym = n.firstSon.symId
    else:
      if isDeclarativen:
        takeTree dest, n
      else:
        copyInto dest, n:
          while n.kind != ParRi:
            inlineRoutineBody(c, dest, n)

proc mapParamToLocal(c: var InlineContext; dest: var TokenBuf; args: var Cursor; params: var Cursor) =
  # assign parameters: This also ensures that side effects are executed,
  # consider: `inlineCall effect(x)` where `inlineCall` does not even use
  # its first parameter!
  assert params.kind != DotToken
  assert params.kind != ParRi
  let p = params
  let r = takeLocal(params, SkipFinalParRi)
  if r.typ.typeKind == VarargsT: params = p
  if isCompileTimeType(r.typ):
    skip args # ignore compile-time parameters for inlining purposes
  else:
    let info = args.info
    copyIntoKind dest, LetS, info:
      let id = r.name.symId
      let freshId = newSymId(c.c[], id)
      dest.addSymDef freshId, info
      dest.addDotToken() # not exported
      dest.addDotToken() # no pragmas
      if typeIsBig(r.typ, c.c.ptrSize) and not constructsValue(args):
        c.newVars[id] = VarReplacement(sym: freshId, needsDeref: true)
        copyIntoKind dest, PtrT, info:
          dest.copyTree(r.typ)
        copyIntoKind dest, AddrX, info:
          tr c.c[], dest, args
      else:
        c.newVars[id] = VarReplacement(sym: freshId, needsDeref: false)
        dest.copyTree(r.typ)
        tr c.c[], dest, args

proc doPartialInline(outer: var Context; dest: var TokenBuf; procCall: var Cursor;
                     routine: Routine; guards: GuardBlock; target: Target) =
  ## Partially inline a function: inline only the guards, then call the function.
  ## If guards cause an early return, the function call is skipped.
  ## Note: Currently guards in the original function will still be evaluated.
  ## Future optimization could skip redundant guard evaluation.
  assert procCall.exprKind in CallKinds
  var c = InlineContext(target: target, resultSym: NoSymId, c: addr outer)

  let info = procCall.info

  # Save the original call for later
  var originalCall = procCall

  # Create a block to handle early returns from guards
  copyIntoKind dest, BlockS, info:
    var labelName = "guardReturnLabel"
    makeLocalSym outer, labelName
    c.returnLabel = pool.syms.getOrIncl(labelName)
    dest.addSymDef c.returnLabel, info

    copyIntoKind dest, StmtsS, info:
      # Map parameters for guard inlining
      var args = procCall
      inc args  # skip (call
      var fnSym = args
      inc args  # skip function symbol
      var params = routine.params

      # Map parameters to locals (same as full inlining)
      var savedParams = params
      while args.kind != ParRi:
        if params.kind != DotToken and params.kind == ParLe and params.substructureKind == ParamsU:
          if savedParams == params:  # First time, skip (params
            inc params
          if params.symKind == ParamY:
            mapParamToLocal(c, dest, args, params)
          else:
            inc params
        skip args

      # Inline the guard statements
      var guardStmt = guards.guardStart
      while guardStmt != guards.guardEnd and guardStmt.kind != ParRi:
        inlineRoutineBody(c, dest, guardStmt)

      # After guards, if we haven't returned (check returnLabel via cfvar or just continue),
      # call the function. For now, we always call - redundant guards will be optimized later.
      # Copy the original function call
      copyTree dest, originalCall

  # If target expects a result, we need to handle it
  if target.kind != TargetIsNone:
    # Result is handled by the function call, which we've already inlined above
    discard

proc doInline(outer: var Context; dest: var TokenBuf; procCall: var Cursor; routine: Routine;
              target: Target) =
  assert procCall.exprKind in CallKinds
  var c = InlineContext(target: target, resultSym: NoSymId, c: addr outer)

  let info = procCall.info

  var isStmtListExpr = false
  if target.kind == TargetIsNone:
    let t = getType(outer.typeCache, procCall)
    if t.typeKind != VoidT:
      dest.addParLe ExprX, info
      isStmtListExpr = true

  copyIntoKind dest, BlockS, info:
    var labelName = "returnLabel"
    makeLocalSym outer, labelName
    c.returnLabel = pool.syms.getOrIncl(labelName)
    dest.addSymDef c.returnLabel, info

    copyIntoKind dest, StmtsS, info:
      inc procCall # skip `(call`
      takeTree dest, procCall # `fn`
      var params = routine.params
      while procCall.kind != ParRi:
        mapParamToLocal(c, dest, procCall, params)

      var procBody = routine.body
      inlineRoutineBody(c, dest, procBody)

  if isStmtListExpr:
    let toReplace = c.newVars.getOrDefault(c.resultSym)
    assert toReplace.sym != NoSymId, "cannot find result declaration"
    addVarReplacement(dest, toReplace, info)
    dest.addParRi()

proc trAsgn(c: var Context; dest: var TokenBuf; n: var Cursor) =
  let le = n.firstSon
  var ri = le
  skip ri
  var routine = default(Routine)
  let inlineMode = shouldInlineCall(c, ri, routine)
  case inlineMode
  of FullInline:
    if le.kind == Symbol:
      # target is simple enough to do store forwarding from `result/return` to `le`:
      doInline(c, dest, ri, routine, Target(kind: TargetIsNode, pos: le))
    else:
      copyInto dest, n:
        tr c, dest, n
        doInline(c, dest, n, routine, Target(kind: TargetIsNone))
  of PartialInline:
    let guards = extractGuards(routine.body)
    if guards.hasGuards:
      if le.kind == Symbol:
        doPartialInline(c, dest, ri, routine, guards, Target(kind: TargetIsNode, pos: le))
      else:
        copyInto dest, n:
          tr c, dest, n
          doPartialInline(c, dest, n, routine, guards, Target(kind: TargetIsNone))
    else:
      # Fallback to no inlining if guards extraction failed
      copyInto dest, n:
        tr c, dest, n
        tr c, dest, n
  of NoInline:
    copyInto dest, n:
      tr c, dest, n
      tr c, dest, n

proc trLocalDecl(c: var Context; dest: var TokenBuf; n: var Cursor) =
  var r = takeLocal(n, SkipFinalParRi)
  var routine = default(Routine)
  let inlineMode = shouldInlineCall(c, r.val, routine)
  copyInto dest, n:
    copyTree dest, r.name
    copyTree dest, r.exported
    copyTree dest, r.pragmas
    copyTree dest, r.typ
    c.typeCache.registerLocal(r.name.symId, r.kind, r.typ)
    if inlineMode != NoInline:
      addEmpty dest, r.val.info
    else:
      tr c, dest, r.val

  case inlineMode
  of FullInline:
    doInline(c, dest, r.val, routine, Target(kind: TargetIsSym, sym: r.name.symId))
  of PartialInline:
    let guards = extractGuards(routine.body)
    if guards.hasGuards:
      doPartialInline(c, dest, r.val, routine, guards, Target(kind: TargetIsSym, sym: r.name.symId))
    # else: already copied above, no inlining
  of NoInline:
    discard  # already handled above

proc tr(c: var Context; dest: var TokenBuf; n: var Cursor) =
  var nested = 0
  while true:
    case n.kind
    of Symbol, SymbolDef, Ident, IntLit, UIntLit, FloatLit, CharLit, StringLit, UnknownToken, DotToken, EofToken:
      dest.add n
      inc n
    of ParLe:
      case n.stmtKind
      of AsgnS:
        trAsgn c, dest, n
      of LocalDecls:
        trLocalDecl c, dest, n
      of ProcS, FuncS, MacroS, MethodS, ConverterS:
        trProcDecl c, dest, n
      of ScopeS:
        c.typeCache.openScope()
        dest.add n
        inc n
        while n.kind != ParRi:
          tr c, dest, n
        c.typeCache.closeScope()
      else:
        if n.exprKind in CallKinds:
          var routine = default(Routine)
          let inlineMode = shouldInlineCall(c, n, routine)
          case inlineMode
          of FullInline:
            doInline(c, dest, n, routine, Target(kind: TargetIsNone))
          of PartialInline:
            let guards = extractGuards(routine.body)
            if guards.hasGuards:
              doPartialInline(c, dest, n, routine, guards, Target(kind: TargetIsNone))
            else:
              dest.add n
              inc nested
              inc n
          of NoInline:
            dest.add n
            inc nested
            inc n
        elif isDeclarativen:
          takeTree dest, n
        else:
          dest.add n
          inc nested
          inc n
    of ParRi:
      dest.add n
      dec nested
      inc n
    if nested == 0: break

proc inlineCalls*(n: Cursor; thisModuleSuffix: string; ptrSize: int): TokenBuf =
  var c = createInliner(thisModuleSuffix, ptrSize)
  c.typeCache.openScope()
  result = createTokenBuf(300)
  var n = n
  tr(c, result, n)
  #result = lowerExprs(p, result)
  c.typeCache.closeScope()
