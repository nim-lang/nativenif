#!/usr/bin/env bash
# Byte-identity gate for the module-layout refactor (doc/internals/module_layout.md).
#
# A pure code move has no licence to produce a different byte. This drives the
# WHOLE corpus through arkham (every target) and nifasm, and writes one sorted
# line per artifact: either its sha256 or the exit code + the diagnostic the
# tool printed. Capture it once on a known-good tree, re-run it after every
# stage, `diff` the two.
#
#   tools/refactor_gate.sh baseline.sums     # before
#   tools/refactor_gate.sh after.sums        # after a stage
#   diff baseline.sums after.sums            # must be empty
#
# SKIP_BUILD=1 reuses bin/arkham and bin/nifasm as they are.
set -u

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

out=${1:-refgate.sums}
work=nimcache/refgate
arkham=bin/arkham
nifasm=bin/nifasm

if [ "${SKIP_BUILD:-0}" != "1" ]; then
  nim c --hints:off src/arkham/arkham.nim >/dev/null || exit 1
  nim c --hints:off -o:bin/nifasm src/nifasm/nifasm.nim >/dev/null || exit 1
fi

rm -rf "$work"
tmp=$(mktemp)

# A tool's diagnostic is part of its observable behaviour, so a failing fixture
# is recorded too — but the Nim stack trace `nifasm`'s `error` prints names
# source lines that this refactor moves BY DESIGN, so those lines are dropped
# and only the message survives.
strip_trace() { grep -v -e '\.nim(' -e '^Traceback' -e '^Error: unhandled exception' || true; }

# record <label> <exitcode> <outputfile> <artifact-or-empty>
record() {
  local label=$1 code=$2 log=$3 art=${4:-}
  if [ "$code" = "0" ] && [ -n "$art" ] && [ -f "$art" ]; then
    printf '%s\t%s\n' "$label" "$(sha256sum < "$art" | cut -d' ' -f1)" >> "$tmp"
  else
    printf '%s\tEXIT:%s\t%s\n' "$label" "$code" \
      "$(strip_trace < "$log" | tr '\n' '|' | cut -c1-300)" >> "$tmp"
  fi
}

run_corpus() { # <srcdir> <arch> [extra arkham flags]
  local srcdir=$1 arch=$2; shift 2
  local dir="$work/$arch-$(basename "$srcdir")"
  mkdir -p "$dir"
  local f name asmnif img log
  log=$(mktemp)
  for f in "$srcdir"/*.c.nif; do
    [ -e "$f" ] || continue
    name=$(basename "$f" .c.nif)
    asmnif="$dir/$name.asm.nif"
    "$arkham" -a:"$arch" "$@" -o:"$asmnif" "$f" > "$log" 2>&1
    record "arkham/$arch/$name" "$?" "$log" "$asmnif"
  done
  # Assemble second, in a separate sweep: nifasm resolves a foreign module by
  # looking for `<name>.asm.nif` beside its input, so every fixture of this arch
  # has to exist before any of them is assembled.
  for asmnif in "$dir"/*.asm.nif; do
    [ -e "$asmnif" ] || continue
    name=$(basename "$asmnif" .asm.nif)
    img="$dir/$name.img"
    "$nifasm" -o:"$img" "$asmnif" > "$log" 2>&1
    record "nifasm/$arch/$name" "$?" "$log" "$img"
  done
  rm -f "$log"
}

run_corpus tests/arkham x64
run_corpus tests/arkham win_x64
run_corpus tests/arkham arm64
run_corpus tests/arkham linux_arm64
run_corpus tests/arkham cortex_m
run_corpus tests/arkham_m cortex_m

# The hand-written asm-NIF fixtures go straight through nifasm. They live beside
# each other in `tests/`, which is also where their cross-module imports resolve,
# so they are assembled in place with the output parked under $work.
mkdir -p "$work/asmnif"
log=$(mktemp)
for f in tests/*.nif; do
  name=$(basename "$f" .nif)
  img="$work/asmnif/$name.img"
  "$nifasm" -o:"$img" "$f" > "$log" 2>&1
  record "nifasm/raw/$name" "$?" "$log" "$img"
done
rm -f "$log"

LC_ALL=C sort "$tmp" > "$out"
rm -f "$tmp"
echo "$(wc -l < "$out") artifacts -> $out"
