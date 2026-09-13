#!/bin/bash
# Run TLC on the call-argument marshalling model: the correct protocol, then each
# bug injection, comparing every verdict with the expected one. Exit status 0 iff
# all seven agree.
#
#   none          two phases; parks: survivor / pool-outside-the-claims / memory   pass
#   survivorOnly  the old takeHeld(canSpill = false)                               FAIL (NotStuck)
#   noAvoid       a pool park may sit where a later argument is loaded             FAIL
#   noBound       the pool ignores what a register holds                           FAIL
#   noLaterClob   every computed scalar into its own ABI register                  FAIL
#   earlyLoad     leaves/aggregates loaded in phase 1 (the old fused loop)         FAIL
#   noPhase0      an argument homed in another argument's register not parked     FAIL
# Two more rows are reachability probes on the correct spec: `NoPoolPark` and
# `NoMemPark` must FAIL, or the pool / memory tiers were never exercised.

set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
YRC_PROOF_DIR="$(cd "$SCRIPT_DIR/../../yrc-proof" 2>/dev/null && pwd || true)"
cd "$SCRIPT_DIR"

if command -v tlc >/dev/null 2>&1; then TLC=(tlc)
elif [ -n "$YRC_PROOF_DIR" ] && [ -x "$YRC_PROOF_DIR/tlc" ]; then TLC=("$YRC_PROOF_DIR/tlc")
elif [ -n "$YRC_PROOF_DIR" ] && [ -f "$YRC_PROOF_DIR/tla/tla2tools.jar" ]; then
  TLC=(java -XX:+UseParallelGC -cp "$YRC_PROOF_DIR/tla/tla2tools.jar" tlc2.TLC)
elif [ -f "$HOME/tla2tools.jar" ]; then TLC=(java -XX:+UseParallelGC -cp "$HOME/tla2tools.jar" tlc2.TLC)
else echo "TLC not found." >&2; exit 1; fi

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
cp call_marshal.tla "$TMP/"
status=0
for row in none:pass: survivorOnly:FAIL:NotStuck noAvoid:FAIL:ParksIntact \
           noBound:FAIL:ParksIntact noLaterClob:FAIL:ParksIntact \
           earlyLoad:FAIL:LoadedIntact noPhase0:FAIL:LoadedIntact \
           probe-NoPoolPark:FAIL:NoPoolPark \
           probe-NoMemPark:FAIL:NoMemPark; do
  IFS=: read -r bug want wantInv <<<"$row"
  if [[ "$bug" == probe-* ]]; then
    sed -e "/^INVARIANT/d" call_marshal.cfg > "$TMP/$bug.cfg"
    echo "INVARIANT ${bug#probe-}" >> "$TMP/$bug.cfg"
  else
    sed -e "s/Bug = \"none\"/Bug = \"$bug\"/" call_marshal.cfg > "$TMP/$bug.cfg"
  fi
  out="$("${TLC[@]}" -metadir "$TMP/meta-$bug" -config "$TMP/$bug.cfg" \
        "$TMP/call_marshal.tla" 2>&1)"
  if grep -q "No error has been found" <<<"$out"; then got=pass
  elif grep -q "is violated" <<<"$out"; then got=FAIL
  else got=ERROR; echo "$out" | tail -20; fi
  states="$(grep -oE '[0-9,]+ distinct states found' <<<"$out" | tail -1 | tr -d , | grep -oE '^[0-9]+')"
  inv="$(grep -oE 'Invariant [A-Za-z]+ is violated' <<<"$out" | head -1 | awk '{print $2}')"
  mark=ok
  [ "$got" = "$want" ] || mark=MISMATCH
  [ -z "$wantInv" ] || [ "$inv" = "$wantInv" ] || mark=MISMATCH
  [ $mark = ok ] || status=1
  printf '%-17s expected %-5s %-17s got %-5s %-17s %6s states  %s\n' \
         "$bug" "$want" "$wantInv" "$got" "${inv:-}" "${states:-?}" "$mark"
done
exit $status
