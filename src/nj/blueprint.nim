
import "../../../nimony/src/lib" / [nifreader, nifstreams, nifcursors, bitabs, lineinfos, symparser]
import model, kinds

type
  Context = object

proc typeSymbol(c: var Context; dest: var TokenBuf; n: var Cursor) =
  dest.add n
  inc n

proc typeSymbolDef(c: var Context; dest: var TokenBuf; n: var Cursor) =
  dest.add n
  inc n

proc trType(c: var Context; dest: var TokenBuf; n: var Cursor) =
  case n.kind
  of Symbol:
    typeSymbol c, dest, n
  of SymbolDef:
    typeSymbolDef c, dest, n
  of UnknownToken, EofToken, DotToken, Ident, StringLit, CharLit, IntLit, UIntLit, FloatLit:
    dest.add n
    inc n
  of ParLe:
    case n.typeKind
    of NoType:
      bug "type expected"
    of UnionT, ObjectT, ProctypeT, IT, UT, FT, CT, BoolT, VoidT, PtrT, ArrayT, FlexarrayT, AptrT, PointerT:
      inc n
      while n.kind != ParRi:
        trType c, dest, n
      inc n
  of ParRi:
    bug "ParRi in weird position"

proc exprSymbol(c: var Context; dest: var TokenBuf; n: var Cursor) =
  dest.add n
  inc n

proc trExpr(c: var Context; dest: var TokenBuf; n: var Cursor) =
  case n.exprKind
  of NoExpr:
    case n.kind
    of Symbol:
      exprSymbol c, dest, n
    of SymbolDef:
      bug "SymbolDef in expression context"
    of UnknownToken, EofToken, DotToken, Ident, StringLit, CharLit, IntLit, UIntLit, FloatLit:
      dest.add n
      inc n
    of ParLe:
      bug "ParLe in weird position"
    of ParRi:
      bug "ParRi in weird position"
  of SufX, AtX, DerefX, DotX, PatX, ParX, AddrX, NilX, InfX, NeginfX, NanX, FalseX, TrueX, NotX, NegX,
     SizeofX, AlignofX, OffsetofX, OconstrX, AconstrX, OvfX, AddX, SubX, MulX, DivX, ModX, ShrX, ShlX,
     BitandX, BitorX, BitxorX, BitnotX, EqX, NeqX, LeX, LtX, CastX, ConvX, VX, AshrX, BaseobjX:
    inc n
    while n.kind != ParRi:
      trExpr c, dest, n
    inc n

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
    inc n
    while n.kind != ParRi:
      trStmt c, dest, n
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


