---------------------------- MODULE regproto ----------------------------
(* TLA+ mirror of regproto.nif — the arkham fused-emitter register/temp   *)
(* protocol. Kept in sync with the NIF spec so TLC can cross-validate     *)
(* tlanif (state counts must match) and serve as a performance baseline.  *)
(* Run:  java -jar tla2tools.jar -workers N -deadlock -checkpoint 0       *)
(*       -config regproto.cfg regproto.tla                                *)

EXTENDS Naturals, FiniteSets

CONSTANTS Vals, HeldRegs, PoolRegs, Bridges, Slots, NoLoc

Regs == HeldRegs \cup PoolRegs \cup Bridges
Clobber == PoolRegs \cup Bridges

VARIABLES status, loc, written, picked, callPending, badRead

vars == <<status, loc, written, picked, callPending, badRead>>

sFree == 0
sWants == 1
sReserved == 2
sBound == 3
sDead == 4

LocFree(L) ==
  \A w \in Vals:
    (status[w] \in {sReserved, sBound}) => loc[w] # L

RegAvail(L) == L \notin picked /\ LocFree(L)

HeldAvail == \E L \in HeldRegs: RegAvail(L)
PoolAvail == \E L \in PoolRegs: RegAvail(L)
BridgeAvail == \E L \in Bridges: RegAvail(L)
SlotAvail == \E L \in Slots: LocFree(L)

Init ==
  /\ status = [v \in Vals |-> sFree]
  /\ loc = [v \in Vals |-> NoLoc]
  /\ written = [v \in Vals |-> FALSE]
  /\ picked = {}
  /\ callPending = FALSE
  /\ badRead = FALSE

Want ==
  \E v \in Vals:
    /\ status[v] = sFree
    /\ \A w \in Vals: status[w] # sWants
    /\ status' = [status EXCEPT ![v] = sWants]
    /\ UNCHANGED <<loc, written, picked, callPending, badRead>>

ResolveHeld ==
  \E v \in Vals:
    /\ status[v] = sWants
    /\ \E L \in HeldRegs:
         /\ RegAvail(L)
         /\ status' = [status EXCEPT ![v] = sReserved]
         /\ loc' = [loc EXCEPT ![v] = L]
         /\ picked' = picked \cup {L}
    /\ UNCHANGED <<written, callPending, badRead>>

ResolvePool ==
  \E v \in Vals:
    /\ status[v] = sWants
    /\ ~HeldAvail
    /\ \E L \in PoolRegs:
         /\ RegAvail(L)
         /\ status' = [status EXCEPT ![v] = sReserved]
         /\ loc' = [loc EXCEPT ![v] = L]
         /\ picked' = picked \cup {L}
    /\ UNCHANGED <<written, callPending, badRead>>

ResolveBridge ==
  \E v \in Vals:
    /\ status[v] = sWants
    /\ ~HeldAvail
    /\ ~PoolAvail
    /\ \E L \in Bridges:
         /\ RegAvail(L)
         /\ status' = [status EXCEPT ![v] = sReserved]
         /\ loc' = [loc EXCEPT ![v] = L]
         /\ picked' = picked \cup {L}
    /\ UNCHANGED <<written, callPending, badRead>>

ResolveSpill ==
  \E v \in Vals:
    /\ status[v] = sWants
    /\ ~HeldAvail
    /\ ~PoolAvail
    /\ ~BridgeAvail
    /\ \E L \in Slots:
         /\ LocFree(L)
         /\ status' = [status EXCEPT ![v] = sReserved]
         /\ loc' = [loc EXCEPT ![v] = L]
    /\ UNCHANGED <<written, picked, callPending, badRead>>

Materialize ==
  \E v \in Vals:
    /\ status[v] = sReserved
    /\ status' = [status EXCEPT ![v] = sBound]
    /\ written' = [written EXCEPT ![v] = TRUE]
    /\ picked' = picked \ {loc[v]}
    /\ UNCHANGED <<loc, callPending, badRead>>

Cancel ==
  \E v \in Vals:
    /\ status[v] = sReserved
    /\ status' = [status EXCEPT ![v] = sDead]
    /\ loc' = [loc EXCEPT ![v] = NoLoc]
    /\ picked' = picked \ {loc[v]}
    /\ UNCHANGED <<written, callPending, badRead>>

Consume ==
  \E v \in Vals:
    /\ status[v] = sBound
    /\ status' = [status EXCEPT ![v] = sDead]
    /\ loc' = [loc EXCEPT ![v] = NoLoc]
    /\ badRead' = badRead \/ ~written[v]
    /\ UNCHANGED <<written, picked, callPending>>

RequestCall ==
  /\ callPending = FALSE
  /\ \E v \in Vals: status[v] = sBound
  /\ callPending' = TRUE
  /\ UNCHANGED <<status, loc, written, picked, badRead>>

ParkToHeld ==
  \E v \in Vals:
    /\ callPending = TRUE
    /\ status[v] = sBound
    /\ loc[v] \in Clobber
    /\ \E L \in HeldRegs:
         /\ RegAvail(L)
         /\ loc' = [loc EXCEPT ![v] = L]
    /\ UNCHANGED <<status, written, picked, callPending, badRead>>

ParkToSlot ==
  \E v \in Vals:
    /\ callPending = TRUE
    /\ status[v] = sBound
    /\ loc[v] \in Clobber
    /\ ~HeldAvail
    /\ \E L \in Slots:
         /\ LocFree(L)
         /\ loc' = [loc EXCEPT ![v] = L]
    /\ UNCHANGED <<status, written, picked, callPending, badRead>>

CallExec ==
  /\ callPending = TRUE
  /\ \A v \in Vals:
       (status[v] = sBound) => loc[v] \notin Clobber
  /\ callPending' = FALSE
  /\ UNCHANGED <<status, loc, written, picked, badRead>>

Next ==
  \/ Want
  \/ ResolveHeld \/ ResolvePool \/ ResolveBridge \/ ResolveSpill
  \/ Materialize \/ Cancel \/ Consume
  \/ RequestCall \/ ParkToHeld \/ ParkToSlot \/ CallExec

Spec == Init /\ [][Next]_vars

Live(w) == status[w] \in {sReserved, sBound}

Excl ==
  \A w, u \in Vals:
    (w # u /\ Live(w) /\ Live(u)) => loc[w] # loc[u]

PickAccounted ==
  /\ \A L \in picked:
       \E w \in Vals: status[w] = sReserved /\ loc[w] = L
  /\ \A w \in Vals:
       (status[w] = sReserved /\ loc[w] \in Regs) => loc[w] \in picked

DemandTotal ==
  (\E w \in Vals: status[w] = sWants) =>
    (HeldAvail \/ PoolAvail \/ BridgeAvail \/ SlotAvail)

ParkTotal ==
  (callPending /\ \E w \in Vals: status[w] = sBound /\ loc[w] \in Clobber) =>
    (HeldAvail \/ SlotAvail)

Inv == Excl /\ PickAccounted /\ ~badRead /\ DemandTotal /\ ParkTotal

==========================================================================
