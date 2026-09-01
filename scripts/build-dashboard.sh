#!/usr/bin/env bash
# Build React dashboard → deploy/dashboard/ (served by intelligence plane).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
UI="$ROOT/deploy/dashboard-ui"

if ! command -v npm >/dev/null 2>&1; then
  echo "npm required to build dashboard" >&2
  exit 1
fi

cd "$UI"
if [ ! -d node_modules ]; then
  npm install
fi
npm run build
echo "Dashboard built → deploy/dashboard/"

if [ -x "$ROOT/scripts/build-attack-map-pdf.sh" ]; then
  "$ROOT/scripts/build-attack-map-pdf.sh" || echo "Note: attack-map PDF skipped (install pandoc for PDF guide)"
fi
