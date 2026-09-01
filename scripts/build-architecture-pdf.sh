#!/usr/bin/env bash
# Build CyberSnare-Architecture-Lab.pdf from docs/src/04-architecture-lab.md
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/docs/src/04-architecture-lab.md"
OUT="$ROOT/docs/CyberSnare-Architecture-Lab.pdf"

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
  -V fontsize=11pt \
  -V documentclass=article \
  -V colorlinks=true \
  -V linkcolor=Blue \
  -V urlcolor=Blue \
  --toc \
  --toc-depth=2 \
  -V title="CyberSnare — Full Lab Architecture" \
  -V author="CyberSnare FYP · Milestone 1" \
  -V date="August 2026"

echo "Built: $OUT ($(du -h "$OUT" | cut -f1))"
