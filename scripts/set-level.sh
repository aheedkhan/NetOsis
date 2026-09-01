#!/usr/bin/env bash
# Pin a manifest level for lab testing (surfaces poll decision /v1/manifest every ~2s).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LEVEL="${1:-L2}"
LEVEL_LOWER="$(printf '%s' "$LEVEL" | tr '[:upper:]' '[:lower:]')"
SRC="$ROOT/config/manifest-${LEVEL_LOWER}.json"
DST="$ROOT/data/manifests/current.json"
PIN="$ROOT/data/manifests/.pinned"

if [ ! -f "$SRC" ]; then
  echo "Unknown level: $LEVEL (no $SRC)" >&2
  exit 1
fi

mkdir -p "$ROOT/data/manifests"
cp "$SRC" "$DST"
touch "$PIN"

# Push pinned manifest into the running decision plane when reachable.
if command -v curl >/dev/null 2>&1; then
  if curl -sf --max-time 2 http://127.0.0.1:19000/health >/dev/null 2>&1; then
    curl -sf --max-time 3 -X POST http://127.0.0.1:19000/v1/manifest/pin \
      -H 'Content-Type: application/json' \
      --data-binary @"$DST" >/dev/null || true
  fi
fi

echo "Manifest pinned to $LEVEL — actuators reconcile within ~2s."
echo "Auth: see capabilities in $SRC"
if [ "$LEVEL_LOWER" = "l2" ] || [ "$LEVEL_LOWER" = "l3" ]; then
  echo "SSH test: ssh -p 2222 guest@127.0.0.1  (password in config/shell-users.json)"
fi
