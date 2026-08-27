#
#           Arkham — the emitter's transient-register budget
#        (c) Copyright 2026 Andreas Rumpf
#
#    See the file "license.txt", included in this distribution.
#

## The accounting behind design.md, "Making the reservation a bound instead of a
## measurement". Both back ends have a small set of registers the ALLOCATOR never
## assigns, which the emitter draws transients from; what differs is only how the
## set is spelled and how much of it is GUARANTEED.
##
##  * the RISC targets reserve `md.bridgeRegs` outright — capacity and guarantee
##    are the same number, at least `EmitterBridgeDemand` (exactly that on RV32,
##    one more on both Arm targets);
##  * x86-64 reserves ONE (R11) and treats the ABI volatiles as extra capacity
##    when they happen to be free, so its capacity is dynamic and larger than its
##    guarantee.
##
## Three numbers therefore reach every check rather than one, and keeping them
## apart is what lets the same code serve both:
##
##  * `live` — held right now, by this step and every enclosing one;
##  * `capacity` — how many could be drawn at this moment;
##  * `guaranteed` — how many the target promises REGARDLESS of what the
##    allocator did. The gap between the last two is exactly the thing design.md
##    calls x86-64's open question, and `tightCompositions` counts it.

import machinedesc, context

const BridgeCheck* = defined(arkhamStress) or defined(arkhamBridgeCheck) or
                     not defined(release)
  ## Whether the budget assertions are compiled in. ON in a debug build and in
  ## every `-d:arkhamStress` binary — the pool-dry pass is exactly where the
  ## margin is thin — and OFF in a shipped release build, where they would cost a
  ## register walk per recursive emit call for a property the stress pass has
  ## already established over the whole corpus.

var tightCompositions*: int = 0
  ## How many times a step was entered with less than its DECLARED worst case
  ## GUARANTEED. A declaration is static and demand is not, so this is "unproven",
  ## not "wrong" — made an error it would reject compositions that provably never
  ## bite, ignored it would hide the ones that eventually will.

var lastResortTakes*: int = 0
  ## How many times a step took a transient past its declaration because every
  ## alternative was gone. Counted, never asserted: a step that exhausts its
  ## alternatives and says so is behaving correctly, and refusing it there would
  ## trade a budget overrun for a hard out-of-registers, which is worse.

proc bridgeBudgetFailed*(g: CodeGen; what: string; need, live, capacity: int;
                         held: string) {.noinline.} =
  ## Two different failures wear this assertion, and they want different fixes.
  let head = "arkham " & g.md.targetName & ": bridge budget — " & what &
             " needs " & $need & " of " & $capacity & " reserved"
  if need > capacity:
    # Not a composition at all: the step does not fit this machine even alone.
    raiseAssert head & ", which is more than this target reserves, in proc " &
      g.curProcName & ". Either the machine model is short one (RV32 shipped " &
      "`[R29, R30, R30]` and had two where it claimed three — see " &
      "`machinedesc.checkMachine`) or the step must be written to a smaller " &
      "budget: see design.md, I3."
  raiseAssert head & ", but " & $live & " (" & held &
    ") are already held by an ENCLOSING step, in proc " & g.curProcName &
    ". A COMPOSITION failure, not pressure: the allocator never owns these " &
    "registers, so no amount of spilling elsewhere frees one, and the step that " &
    "fails is not the step that is wrong. The fix belongs to the HOLDER — it " &
    "must release across the recursion, the way `genNestedAggrField` builds its " &
    "value into a frame slot BEFORE taking its bridges. See design.md, I1."

proc bridgeScopePush*(g: var CodeGen; demand: BridgeDemand; what: string;
                      live, capacity, guaranteed: int; held: string) =
  ## Open a declared scope. Two conditions, and keeping them apart is the whole
  ## content of this proc.
  ##
  ##  * **Progress**, an ERROR. A step entered with nothing available cannot emit
  ##    anything at all, whatever it turns out to be.
  ##  * **Worst case**, a COUNT. A step that declares two is not obliged to take
  ##    two on this path, so being entered with less than that GUARANTEED is not
  ##    yet wrong — it is only unproven.
  if live + 1 > capacity:
    if g.lastResortBridges == {}:
      bridgeBudgetFailed(g, what, 1, live, capacity, held)
    else:
      # A step already went past its declaration because it had nothing else, so
      # the emitter is knowingly outside its budget until that register comes
      # back. The escape working, not an unaccounted composition.
      inc tightCompositions
  if live + ord(demand) > guaranteed:
    inc tightCompositions
  g.bridgeScopes.add (base: live, cap: ord(demand), what: what)

proc bridgeScopePop*(g: var CodeGen; live: int; held: string) =
  ## Close it, checking the step gave back exactly what it took. A LEAK is not a
  ## crash and never would be — the register stays bound and the next step
  ## silently runs with one fewer, until something far away asserts.
  let sc = g.bridgeScopes.pop()
  if getCurrentException() != nil:
    # Unwinding already. A step abandoned mid-way has of course not released its
    # registers, so the leak below is a CONSEQUENCE of the failure in flight and
    # raising it here would replace the real diagnostic with a derived one —
    # which is exactly what it did on first use.
    return
  if live > sc.base:
    raiseAssert "arkham " & g.md.targetName & ": bridge leak — " & sc.what &
      " left " & $(live - sc.base) & " of its " & $sc.cap &
      " declared transient(s) still held (" & held & ") in proc " &
      g.curProcName & ". Every take needs its release on every path out."

proc bridgeOverDeclared*(g: CodeGen; live: int) {.noinline.} =
  let sc = g.bridgeScopes[^1]
  raiseAssert "arkham " & g.md.targetName & ": bridge budget — " & sc.what &
    " declared " & $sc.cap & " transient(s) and is taking " &
    $(live - sc.base + 1) & ", in proc " & g.curProcName &
    ". Raise the declaration to the matching `BridgeDemand` member if the step " &
    "really holds that many at once — which forces every machine model to " &
    "reserve one more (`machinedesc.checkMachine`) and is meant to be a " &
    "decision, not a default. Otherwise the step is holding a register it could " &
    "have released: see design.md, I2."

proc bridgeRaise*(g: var CodeGen; demand: BridgeDemand; what: string;
                  guaranteed: int) =
  ## Widen the innermost declaration for the rest of the current step, for a
  ## demand a step only discovers as it runs. Not a new scope: the registers are
  ## taken by one proc and released by another, a lifetime that deliberately
  ## spans several and belongs to the enclosing step, so it is that step's
  ## declaration that has to grow — and it reverts when that step's scope pops.
  if g.bridgeScopes.len > 0 and ord(demand) > g.bridgeScopes[^1].cap:
    g.bridgeScopes[^1].cap = ord(demand)
    g.bridgeScopes[^1].what = what
    if g.bridgeScopes[^1].base + ord(demand) > guaranteed:
      inc tightCompositions

proc bridgeTakeAllowed*(g: CodeGen; live: int): bool {.inline.} =
  ## Whether one more take fits the innermost declaration.
  g.bridgeScopes.len == 0 or live - g.bridgeScopes[^1].base < g.bridgeScopes[^1].cap
