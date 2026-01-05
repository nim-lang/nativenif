| Tag                    | Enums                       |   Description |
|------------------------|-----------------------------|---------------|
| `(at X X)`             | NjExpr | array indexing operation |
| `(deref X)`            | NjExpr | pointer deref operation |
| `(dot X Y)`            | NjExpr | object field selection |
| `(pat X X)`            | NjExpr | pointer indexing operation |
| `(par X)`              | NjExpr | syntactic parenthesis |
| `(addr X)`             | NjExpr | address of operation |
| `(nil T?)`             | NjExpr | nil pointer value |
| `(notnil)`             | NjOther | `not nil` pointer annotation |
| `(inf T?)`             | NjExpr | positive infinity floating point value |
| `(neginf T?)`          | NjExpr | negative infinity floating point value |
| `(nan T?)`             | NjExpr | NaN floating point value |
| `(false)`              | NjExpr | boolean `false` value |
| `(true)`               | NjExpr | boolean `true` value |
| `(not X)`              | NjExpr | boolean `not` operation |
| `(neg X)`              | NjExpr | negation operation |
| `(sizeof T)`           | NjExpr | `sizeof` operation |
| `(alignof T)`          | NjExpr | `alignof` operation |
| `(offsetof T Y)`       | NjExpr | `offsetof` operation |
| `(oconstr T (kv Y X)*)` | NjExpr | object constructor |
| `(aconstr T X*)`       | NjExpr | array constructor |
| `(kv Y X)`             | NjOther | key-value pair |
| `(vv X X)`             | NjOther | value-value pair (used for explicitly named arguments in function calls) |
| `(ovf)`                | NjExpr | access overflow flag |
| `(add T X X)`          | NjExpr | |
| `(sub T X X)`          | NjExpr | |
| `(mul T X X)`          | NjExpr | |
| `(div T X X)`          | NjExpr | |
| `(mod T X X)`          | NjExpr | |
| `(shr T X X)`          | NjExpr | |
| `(shl T X X)`          | NjExpr | |
| `(bitand T X X)`       | NjExpr | |
| `(bitor T X X)`        | NjExpr | |
| `(bitxor T X X)`       | NjExpr | |
| `(bitnot T X)`         | NjExpr | |
| `(eq T X X)`           | NjExpr | |
| `(neq T X X)`          | NjExpr | |
| `(le T X X)`           | NjExpr | |
| `(lt T X X)`           | NjExpr | |
| `(cast T X)`           | NjExpr | `cast` operation |
| `(conv T X)`           | NjExpr | type conversion |
| `(call X X*)`          | NjStmt | call operation |
| `(gvar D P T X)` | NjStmt | global variable declaration |
| `(tvar D P T X)` | NjStmt | thread local variable declaration |
| `(var D P T X)` | NjStmt | variable declaration |
| `(param D P T)` | NjOther | parameter declaration |
| `(const D P T)` | NjStmt | const variable declaration |
| `(result D P T X)` | NjStmt | result variable declaration |
| `(fld D P T)` | NjOther | field declaration |
| `(proc D ...)` | NjStmt | proc declaration |
| `(type D ...)` | NjStmt | type declaration |
| `(store X X)` | NjStmt | `asgn` with reversed operands that reflects evaluation order |
| `(keepovf X X)` | NjStmt | keep overflow flag statement |
| `(stmts S*)` | NjStmt | list of statements |
| `(params (param...)*)` | NjOther | list of proc parameters, also used as a "proc type" |
| `(union (fld ...)*)`; `(union)` | NjType | first one is Nifc union declaration, second one is Nimony union pragma |
| `(object .T (fld ...)*)` | NjType | object type declaration |
| `(proctype . (params...) T P)` | NjType | proc type declaration |
| `(atomic)` | NjTypeQualifier | `atomic` type qualifier for NIFC |
| `(ro)` | NjTypeQualifier | `readonly` (= `const`) type qualifier for NIFC |
| `(restrict)` | NjTypeQualifier | type qualifier for NIFC |
| `(cppref)` | NjTypeQualifier | type qualifier for NIFC that provides a C++ reference |
| `(i INTLIT)` | NjType | `int` builtin type |
| `(u INTLIT)` | NjType | `uint` builtin type |
| `(f INTLIT)` | NjType | `float` builtin type |
| `(c INTLIT)` | NjType | `char` builtin type |
| `(bool)` | NjType | `bool` builtin type |
| `(void)` | NjType | `void` return type |
| `(ptr T)` | NjType | `ptr` type contructor |
| `(array T X)` | NjType | `array` type constructor |
| `(flexarray T)` | NjType | `flexarray` type constructor |
| `(aptr T TQC*)` | NjType | "pointer to array of" type constructor |
| `(cdecl)` | CallConv | `cdecl` calling convention |
| `(stdcall)` | CallConv | `stdcall` calling convention |
| `(safecall)` | CallConv | `safecall` calling convention |
| `(syscall)` | CallConv | `syscall` calling convention |
| `(fastcall)` | CallConv | `fastcall` calling convention |
| `(thiscall)` | CallConv | `thiscall` calling convention |
| `(noconv)` | CallConv | no explicit calling convention |
| `(member)`  | CallConv | `member` calling convention |
| `(nimcall)` | CallConv | `nimcall` calling convention |
| `(inline)` | NjPragma | `inline` proc annotation |
| `(noinline)` | NjPragma | `noinline` proc annotation |
| `(varargs)` | NjPragma | `varargs` proc annotation |
| `(was STR)` | NjPragma | |
| `(align X)` | NjPragma | |
| `(bits X)`| NjPragma | |
| `(ite X S S S?)` | NjStmt | if-then-else followed by optional `join` information |
| `(itec X S S S?)` | NjStmt | if-then-else (that was a `case`) |
| `(loop S X S S)` | NjStmt | `loop` components are (before-cond, cond, loop-body, after) |
| `(v X INT_LIT)` | NjExpr | `versioned` locations |
| `(unknown X)` | NjStmt | location's contents is unknown at this point |
| `(jtrue Y+)` | NjStmt | set variables v1, v2, ... to `(true)`; hint this should become a jump |
| `(cfvar D)` | NjStmt | declare a new control flow variable `D` of type `bool` initialized to `false` |
| `(join Y INT_LIT INT_LIT INT_LIT)` | NjOther | `join` construct inside `ite` |
| `(kill Y)` | NjStmt | some.var is about to disappear (scope exit) |
| `(pointer)` | NjType | `pointer` type |
| `(dynlib X)` | NjPragma | `dynlib` pragma |
| `(exportc X)` | NjPragma | `exportc` pragma |
| `(threadvar)` | NjPragma | `threadvar` pragma |
| `(noreturn)` | NjPragma | `noreturn` pragma |
| `(noinit)` | NjPragma | `noinit` pragma |
| `(requires X)` | NjPragma | `requires` pragma |
| `(ensures X)` | NjPragma | `ensures` pragma |
| `(assume X)` | NjStmt | `assume` pragma/annotation |
| `(assert X)` | NjStmt | `assert` pragma/annotation |
| `(ashr T X X)` | NjExpr | |
| `(baseobj T INTLIT X)` | NjExpr | object conversion to base type |
| `(asm X+)` | NjStmt | `asm` statement |
| `(packed)`   | NjPragma | `packed` pragma |
