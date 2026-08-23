#!/usr/bin/env bash
# Byte-identity gate: assert that `bin/arkham` emits EXACTLY the asm-NIF that the
# frozen `bin/arkham_m1base` emits, for every fixture on every existing target.
#
# This is the safeguard for changes that are supposed to be INERT — the word-size
# parameterization (M1) rewrites code both existing backends run through, so the
# only convincing evidence that x64/a64 are untouched is that not one output byte
# moved.
#
#   usage: ./bytegate.sh [baseline-arkham] [current-arkham]
#
# Run from the repo root. Build the baseline BEFORE the change under test:
#   git stash && nim c -o:bin/arkham_m1base src/arkham/arkham.nim && git stash pop
set -u
BASE=${1:-bin/arkham_m1base}
CUR=${2:-bin/arkham}
[ -x "$BASE" ] || { echo "missing $BASE"; exit 2; }
[ -x "$CUR" ]  || { echo "missing $CUR"; exit 2; }
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
fail=0; n=0; skipped=0
for arch in x64 linux_arm64 arm64 win_x64; do
  for f in tests/arkham/*.c.nif; do
    stem=$(basename "$f" .c.nif)
    # A fixture the BASELINE cannot compile for this target is out of scope: the
    # gate asks whether we changed anything, not whether coverage is complete.
    if ! "$BASE" -a:"$arch" -o:"$TMP/b.nif" "$f" >"$TMP/b.log" 2>&1; then
      skipped=$((skipped+1)); continue
    fi
    "$CUR" -a:"$arch" -o:"$TMP/c.nif" "$f" >"$TMP/c.log" 2>&1
    n=$((n+1))
    if ! cmp -s "$TMP/b.nif" "$TMP/c.nif"; then
      echo "DIFF  $arch  $stem"
      diff <(head -c 4000 "$TMP/b.nif") <(head -c 4000 "$TMP/c.nif") | head -12
      fail=$((fail+1))
    fi
  done
done
echo "bytegate: $n compared, $fail differing, $skipped baseline-unsupported"
[ "$fail" -eq 0 ] || exit 1
