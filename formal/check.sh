#!/bin/sh
# Model-check the register/temp protocol spec and its bug variants.
# The main spec must pass; every regproto_bug_*.nif must be refuted.
# Usage: formal/check.sh [path-to-tlanif]
set -e
cd "$(dirname "$0")"
TLANIF="${1:-$HOME/projects/tlanif/src/tlanif}"
if [ ! -x "$TLANIF" ]; then
  echo "tlanif not found at $TLANIF (build: nim c ~/projects/tlanif/src/tlanif.nim)" >&2
  exit 1
fi

"$TLANIF" --max-states:2000000 regproto.nif || { echo "FAIL: regproto.nif must hold"; exit 1; }

for f in regproto_bug_*.nif; do
  if "$TLANIF" --max-states:2000000 "$f" >/dev/null 2>&1; then
    echo "FAIL: $f must be refuted (bug variant passed the checker)"
    exit 1
  else
    echo "refuted as expected: $f"
  fi
done
echo "formal gate OK"
