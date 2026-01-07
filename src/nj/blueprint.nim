
import "../../../nimony/src/lib" / [nifreader, nifstreams, nifcursors, bitabs, lineinfos, symparser]
import model, kinds

template prepareTraversal(Context: typedesc) {.dirty.} =
  # forward declarations:
  proc trExpr(c: var Context; dest: var TokenBuf; n: var Cursor)
  proc trType(c: var Context; dest: var TokenBuf; n: var Cursor)
  proc trStmt(c: var Context; dest: var TokenBuf; n: var Cursor)

  proc trExprLoop(c: var Context; dest: var TokenBuf; n: var Cursor) =
    while n.kind != ParRi:
      trExpr c, dest, n
    dest.add n
    inc n

template implementTraversal(Context: typedesc; inspectTypes: bool = false) {.dirty.} =
  when inspectTypes:
    proc trType(c: var Context; dest: var TokenBuf; n: var Cursor) =
      case n.kind
      of Symbol:
        trTypeSymbol c, dest, n
      of SymbolDef:
        trTypeSymbolDef c, dest, n
      of StringLit:
        trTypeStringLit c, dest, n
      of CharLit:
        trTypeCharLit c, dest, n
      of IntLit:
        trTypeIntLit c, dest, n
      of UIntLit:
        trTypeUIntLit c, dest, n
      of FloatLit:
        trTypeFloatLit c, dest, n
      of UnknownToken, EofToken, DotToken, Ident:
        dest.add n
        inc n
      of ParLe:
        case n.typeKind
        of NoType:
          bug "type expected"
        of UnionT:
          trUnionBegin c, dest, n
          while n.kind != ParRi:
            trUnionField c, dest, n
          trUnionEnd c, dest, n
        of ObjectT:
          trObjectBegin c, dest, n
          while n.kind != ParRi:
            trObjectField c, dest, n
          trObjectEnd c, dest, n
        of ProctypeT:
          trProctypeBegin c, dest, n
          while n.kind != ParRi:
            trProctypeField c, dest, n
          trProctypeEnd c, dest, n
        of IT:
          trIntType c, dest, n
        of UT:
          trUIntType c, dest, n
        of FT:
          trFloatType c, dest, n
        of CT:
          trCharType c, dest, n
        of BoolT:
          trBoolType c, dest, n
        of VoidT:
          trVoidType c, dest, n
        of PtrT:
          trPtrType c, dest, n
        of ArrayT:
          trArrayType c, dest, n
        of FlexarrayT:
          trFlexarrayType c, dest, n
        of AptrT:
          trAptrType c, dest, n
        of PointerT:
          trPointerType c, dest, n
      of ParRi:
        bug "ParRi in weird position"

  else:
    proc trType(c: var Context; dest: var TokenBuf; n: var Cursor) =
      dest.takeTree n

  proc trExpr(c: var Context; dest: var TokenBuf; n: var Cursor) =
    case n.exprKind
    of NoExpr:
      case n.kind
      of Symbol:
        trExprSymbol c, dest, n
      of SymbolDef:
        bug "SymbolDef in expression context"
      of StringLit:
        trExprStringLit c, dest, n
      of CharLit:
        trExprCharLit c, dest, n
      of IntLit:
        trExprIntLit c, dest, n
      of UIntLit:
        trExprUIntLit c, dest, n
      of FloatLit:
        trExprFloatLit c, dest, n
      of UnknownToken, EofToken, DotToken, Ident:
        dest.add n
        inc n
      of ParLe:
        bug "ParLe in weird position"
      of ParRi:
        bug "ParRi in weird position"
    of AtX:
      trAt c, dest, n
    of DerefX:
      trDeref c, dest, n
    of DotX:
      trDot c, dest, n
    of PatX:
      trPat c, dest, n
    of ParX:
      trPar c, dest, n
    of AddrX:
      trAddr c, dest, n
    of NilX:
      trNil c, dest, n
    of InfX:
      trInf c, dest, n
    of NeginfX:
      trNeginf c, dest, n
    of NanX:
      trNan c, dest, n
    of FalseX:
      trFalse c, dest, n
    of TrueX:
      trTrue c, dest, n
    of NotX:
      trNot c, dest, n
    of NegX:
      trNeg c, dest, n
    of SizeofX:
      trSizeof c, dest, n
    of AlignofX:
      trAlignof c, dest, n
    of OffsetofX:
      trOffsetof c, dest, n
    of OconstrX:
      trOconstr c, dest, n
    of AconstrX:
      trAconstr c, dest, n
    of OvfX:
      trOvf c, dest, n
    of AddX:
      trAdd c, dest, n
    of SubX:
      trSub c, dest, n
    of MulX:
      trMul c, dest, n
    of DivX:
      trDiv c, dest, n
    of ModX:
      trMod c, dest, n
    of ShrX:
      trShr c, dest, n
    of ShlX:
      trShl c, dest, n
    of BitandX:
      trBitand c, dest, n
    of BitorX:
      trBitor c, dest, n
    of BitxorX:
      trBitxor c, dest, n
    of BitnotX:
      trBitnot c, dest, n
    of EqX:
      trEq c, dest, n
    of NeqX:
      trNeq c, dest, n
    of LeX:
      trLe c, dest, n
    of LtX:
      trLt c, dest, n
    of CastX:
      trCast c, dest, n
    of ConvX:
      trConv c, dest, n
    of VX:
      trV c, dest, n
    of AshrX:
      trAshr c, dest, n
    of BaseobjX:
      trBaseobj c, dest, n

  proc trStmt(c: var Context; dest: var TokenBuf; n: var Cursor) =
    case n.stmtKind
    of NoStmt:
      error "statement expected, but got: ", n
    of CallS: trCall c, dest, n
    of GvarS: trGvar c, dest, n
    of TvarS: trTvar c, dest, n
    of VarS: trVar c, dest, n
    of ConstS: trConst c, dest, n
    of ResultS: trResult c, dest, n
    of ProcS: trProc c, dest, n
    of TypeS: trType c, dest, n
    of StoreS: trStore c, dest, n
    of KeepovfS: trKeepovf c, dest, n
    of StmtsS:
      dest.add n
      inc n
      while n.kind != ParRi:
        trStmt c, dest, n
      dest.add n
      inc n
    of IteS, ItecS: trIte c, dest, n
    of LoopS: trLoop c, dest, n
    of UnknownS: trUnknown c, dest, n
    of JtrueS: trJtrue c, dest, n
    of CfvarS: trCfvar c, dest, n
    of KillS: trKill c, dest, n
    of AssumeS: trAssume c, dest, n
    of AssertS: trAssert c, dest, n
    of AsmS: trAsm c, dest, n
