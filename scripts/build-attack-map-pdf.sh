#!/usr/bin/env bash
# Build Attack Map guide PDF → deploy/dashboard/ (served by intelligence plane).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/docs/src/05-attack-map-guide.md"
OUT_DOC="$ROOT/docs/CyberSnare-Attack-Map-Guide.pdf"
OUT_WEB="$ROOT/deploy/dashboard/CyberSnare-Attack-Map-Guide.pdf"

if [ ! -f "$SRC" ]; then
  echo "Missing $SRC" >&2
  exit 1
fi

mkdir -p "$ROOT/deploy/dashboard"

if command -v pandoc >/dev/null 2>&1; then
  pandoc "$SRC" -o "$OUT_DOC" \
    --pdf-engine=xelatex \
    -V geometry:margin=2cm \
    -V fontsize=11pt \
    -V documentclass=article \
    -V colorlinks=true \
    -V linkcolor=Blue \
    -V urlcolor=Blue \
    --toc \
    --toc-depth=2 \
    -V title="CyberSnare — Attack Map Guide" \
    -V subtitle="Flow diagram, phases, and operator instructions" \
    -V author="CyberSnare FYP · Milestone 1" \
    -V date="September 2026"
  cp -f "$OUT_DOC" "$OUT_WEB"
  echo "Built: $OUT_WEB ($(du -h "$OUT_WEB" | cut -f1))"
  exit 0
fi

# Fallback: Python fpdf2 if pandoc unavailable
if python3 -c "import fpdf" 2>/dev/null; then
  python3 "$ROOT/scripts/build-attack-map-pdf.py"
  exit 0
fi

echo "Install pandoc: sudo dnf install -y pandoc texlive-scheme-basic" >&2
echo "  or: pip install fpdf2" >&2
exit 1
