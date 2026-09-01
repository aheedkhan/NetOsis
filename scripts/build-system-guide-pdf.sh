#!/usr/bin/env bash
# Build CyberSnare-System-Guide.pdf from docs/src/06-system-guide.md
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/docs/src/06-system-guide.md"
OUT="$ROOT/docs/CyberSnare-System-Guide.pdf"

if [ ! -f "$SRC" ]; then
  echo "Missing $SRC" >&2
  exit 1
fi

if ! command -v pandoc >/dev/null 2>&1; then
  echo "pandoc required: sudo dnf install -y pandoc texlive-scheme-basic" >&2
  exit 1
fi

pandoc "$SRC" -o "$OUT" \
  --pdf-engine=xelatex \
  -V geometry:margin=2.2cm \
  -V fontsize=10.5pt \
  -V documentclass=article \
  -V colorlinks=true \
  -V linkcolor=Blue \
  -V urlcolor=Blue \
  --toc \
  --toc-depth=2 \
  -V title="CyberSnare — System Guide" \
  -V subtitle="Architecture, components, network, and how to run it" \
  -V author="CyberSnare FYP" \
  -V date="September 2026"

echo "Built: $OUT ($(du -h "$OUT" | cut -f1))"
