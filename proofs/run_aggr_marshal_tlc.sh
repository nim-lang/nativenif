#!/bin/bash
# Run TLC on the aggregate-marshalling model for every strategy x storage kind and
# compare each verdict with the expected one. Exit status 0 iff all eight agree.
#
#   widest   (x64 loadPartialThroughPtr)  pass  pass
#   a64tail  (a64 loadAggrTail)           pass  pass
#   field    (the OLD field-at-offset)    FAIL  FAIL   <- the #170 / lexim miscompile
#   fullword (transferAggrWords)          FAIL  pass   <- correct on a padded slot only
#                                         addr  slot

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
cp aggr_marshal.tla "$TMP/"
status=0
for algo in widest a64tail field fullword; do
  for padded in FALSE TRUE; do
    kind=$([ "$padded" = TRUE ] && echo slot || echo addr)
    case "$algo/$kind" in
      field/*|fullword/addr) want=FAIL ;;
      *) want=pass ;;
    esac
    sed -e "s/Algo = \"widest\"/Algo = \"$algo\"/" -e "s/Padded = FALSE/Padded = $padded/" \
        aggr_marshal.cfg > "$TMP/$algo-$kind.cfg"
    out="$("${TLC[@]}" -metadir "$TMP/meta-$algo-$kind" -config "$TMP/$algo-$kind.cfg" \
          "$TMP/aggr_marshal.tla" 2>&1)"
    if grep -q "No error has been found" <<<"$out"; then got=pass
    elif grep -q "is violated" <<<"$out"; then got=FAIL
    else got=ERROR; echo "$out" | tail -20; fi
    states="$(grep -oE '^[0-9]+ distinct states|[0-9]+ distinct states found' <<<"$out" | grep -oE '^[0-9]+' | head -1)"
    mark=$([ "$got" = "$want" ] && echo ok || { status=1; echo MISMATCH; })
    printf '%-9s %-5s expected %-5s got %-5s %8s states  %s\n' "$algo" "$kind" "$want" "$got" "${states:-?}" "$mark"
  done
done
exit $status
