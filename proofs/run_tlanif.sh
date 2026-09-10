#!/bin/bash
# Check both models with tlanif (the NIF-dialect TLA checker, ../../tlanif) and
# compare the distinct-state counts with TLC's. Exit status 0 iff everything agrees.
#
#   arkham_bindings.nif   MaxLog = 5 ->  584507 states (TLC: 584507; ~6 s with --jobs)
#   aggr_marshal.nif      widest 1170 / a64tail 1268 / fullword-on-a-slot 1144 states,
#                         field and fullword-through-an-address violate the invariant
#
# Usage: run_tlanif.sh [--jobs:N]      (default --jobs:0 = all cores)

set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
JOBS="${1:---jobs:0}"

if command -v tlanif >/dev/null 2>&1; then TLANIF=tlanif
elif [ -x ../../tlanif/bin/tlanif ]; then TLANIF=../../tlanif/bin/tlanif
else echo "tlanif not found: build it with 'nim c -d:release -o:bin/tlanif src/tlanif.nim' in ../../tlanif" >&2; exit 1; fi

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
status=0
check() {  # check <label> <file> <expected: pass|FAIL> <expected states or ->
  local out got states
  out="$("$TLANIF" "$JOBS" --max-states:5000000 "$2" 2>&1)"
  if grep -q "^ok — explored" <<<"$out"; then got=pass
  elif grep -q "invariant violated" <<<"$out"; then got=FAIL
  else got=ERROR; echo "$out" | tail -5; fi
  states="$(grep -oE 'explored [0-9]+' <<<"$out" | grep -oE '[0-9]+')"
  local mark=ok
  [ "$got" = "$3" ] || mark=MISMATCH
  [ "$4" = - ] || [ "${states:-?}" = "$4" ] || mark=MISMATCH
  [ $mark = ok ] || status=1
  printf '%-28s expected %-5s got %-5s %8s states  %s\n' "$1" "$3" "$got" "${states:-?}" "$mark"
}

check "arkham_bindings (MaxLog=5)" arkham_bindings.nif pass 584507
for algo in widest a64tail field fullword; do
  for padded in false true; do
    kind=$([ "$padded" = true ] && echo slot || echo addr)
    case "$algo/$kind" in
      field/*|fullword/addr) want=FAIL; n=- ;;
      widest/*)   want=pass; n=1170 ;;
      a64tail/*)  want=pass; n=1268 ;;
      *)          want=pass; n=1144 ;;
    esac
    sed -e "s/(assign Algo.0. widest.0.)/(assign Algo.0. $algo.0.)/" \
        -e "s/(assign Padded.0. (false))/(assign Padded.0. ($padded))/" \
        aggr_marshal.nif > "$TMP/am-$algo-$kind.nif"
    check "aggr_marshal $algo/$kind" "$TMP/am-$algo-$kind.nif" "$want" "$n"
  done
done
exit $status
