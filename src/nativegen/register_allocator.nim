## NativeNif (c) 2026 Andreas Rumpf

# included from gen_nifasm.nim

#[

Optimistic Kill-instructions Based Register Allocation
----------------------------............--------------

The used strategy is simple and effective. It is not covered by the literature
very well, probably because ultimately it's inferior to a graph based register
allocation strategy. But how can we know without trying...

We traverse the proc body keeping track precisely of the involved scopes. For
every variable that can possibly be kept in a register, we do so until we run
out of registers. If we run out of registers we search the current scope and all
of its parents scopes for a variable that has been assigned a register but has
a lower "weight" (as computed in analyser.nim) as the current one. If so, we
instead put this other variable to the stack and use its register for the current
one.

Notice that this form of "spilling" does not produce any code at all. We simply
undo the register assignment. All this happens before we generate code. There
are 3 passes over a proc body:

1. "Analyse" the variables and their usages, compute their "weights".
2. Perform register allocation.
3. Generate code.

]#

proc stealFrom*(c: var Context; current: SymId; loc: Location; weights: Table[SymId, VarInfo]) =
  let lookFor = if loc.typ.kind == AFloat: InRegFp else: InReg
  for v in c.vars:
    if c.locals[v].kind == lookFor:
      if weights[current].weight > weights[v].weight:
        c.locals[current] = c.locals[v]
        c.locals[v] = loc
        break

proc allocRegsForProc(c: var Context; n: var Cursor; weights: Table[SymId, VarInfo]) =
  case n.stmtKind
  of NoStmt:
    error "statement expected, but got: ", n
  of VarS:
    let v = takeVarDecl(n)
    assert v.name.kind == SymbolDef
    let vn = v.name.symId

    var typ = typeToSlot(c, v.typ)
    let w = weights[vn]
    let loc = allocVar(c.rega, typ, w.props)

    c.locals[vn] = loc
    # did register allocation fail?
    if AddrTaken notin w.props:
      if typ.kind == AFloat:
        if loc.kind != InRegFp:
          stealFrom c, vn, loc, weights
      elif typ.size <= WordSize:
        if loc.kind != InReg:
          stealFrom c, vn, loc, weights

    c.scopes[^1].vars.add vn
    let hasValue = t[v.value].kind != Empty
    if hasValue:
      allocRegsForProc(c, t, v.value, weights)
  of KillS:
    discard
  of IteS, ItecS, StmtsS, LoopS:
    inc n
    while n.kind != ParRi:
      allocRegsForProc(c, n, weights)
    inc n
  else:
    skip n

proc allocateVars*(c: var Context; n: Cursor) =
  var na = n
  let props = analyseVarUsages(na)
  c.locals.clear()
  var nb = n
  allocRegsForProc c, nb, props.vars
