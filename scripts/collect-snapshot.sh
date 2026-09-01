#!/usr/bin/env bash
# Append daily collection snapshot for three-arm study.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
OUT="$ROOT/data/collection/$STAMP"
mkdir -p "$OUT"
cp "$ROOT/data/events/events.jsonl" "$OUT/events.jsonl" 2>/dev/null || true
curl -sf http://127.0.0.1:19000/v1/manifest > "$OUT/manifest.json" 2>/dev/null || true
curl -sf http://127.0.0.1:18090/v1/report > "$OUT/report.json" 2>/dev/null || true
curl -sf http://127.0.0.1:19000/health > "$OUT/decision-health.json" 2>/dev/null || true
echo "Collection snapshot: $OUT"
