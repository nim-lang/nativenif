#!/bin/bash
# Run TLC for the Arkham/nifasm binding protocol model.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
YRC_PROOF_DIR="$(cd "$ROOT_DIR/../yrc-proof" 2>/dev/null && pwd || true)"

cd "$SCRIPT_DIR"

TLC_METADIR="$(mktemp -d)"
trap 'rm -rf "$TLC_METADIR"' EXIT
TLC_ARGS=(-metadir "$TLC_METADIR" -config arkham_bindings.cfg arkham_bindings.tla)

if command -v tlc >/dev/null 2>&1; then
  tlc "${TLC_ARGS[@]}"
elif [ -n "$YRC_PROOF_DIR" ] && [ -x "$YRC_PROOF_DIR/tlc" ]; then
  "$YRC_PROOF_DIR/tlc" "${TLC_ARGS[@]}"
elif [ -n "$YRC_PROOF_DIR" ] && [ -f "$YRC_PROOF_DIR/tla/tla2tools.jar" ]; then
  java -XX:+UseParallelGC -cp "$YRC_PROOF_DIR/tla/tla2tools.jar" tlc2.TLC \
    "${TLC_ARGS[@]}"
elif [ -f "$HOME/tla2tools.jar" ]; then
  java -XX:+UseParallelGC -cp "$HOME/tla2tools.jar" tlc2.TLC \
    "${TLC_ARGS[@]}"
else
  echo "TLC not found. Install TLA+ tools or keep ../yrc-proof/tla/tla2tools.jar available." >&2
  exit 1
fi
