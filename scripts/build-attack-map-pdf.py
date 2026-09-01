#!/usr/bin/env python3
"""Fallback PDF builder when pandoc is not installed (requires fpdf2)."""

from __future__ import annotations

import re
from pathlib import Path

from fpdf import FPDF

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "docs/src/05-attack-map-guide.md"
OUT_DOC = ROOT / "docs/CyberSnare-Attack-Map-Guide.pdf"
OUT_WEB = ROOT / "deploy/dashboard/CyberSnare-Attack-Map-Guide.pdf"


def strip_md(line: str) -> str:
    line = re.sub(r"\*\*([^*]+)\*\*", r"\1", line)
    line = re.sub(r"`([^`]+)`", r"\1", line)
    return line.strip()


def main() -> None:
    text = SRC.read_text(encoding="utf-8")
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "CyberSnare - Attack Map Guide", ln=True)
    pdf.set_font("Helvetica", "", 10)
    pdf.multi_cell(0, 6, "Flow diagram, attack phases, and dashboard operator instructions.")
    pdf.ln(4)

    for raw in text.splitlines():
        line = strip_md(raw)
        if not line or line == "---":
            continue
        if line.startswith("# "):
            pdf.ln(4)
            pdf.set_font("Helvetica", "B", 14)
            pdf.multi_cell(0, 7, line[2:])
            continue
        if line.startswith("## "):
            pdf.ln(3)
            pdf.set_font("Helvetica", "B", 12)
            pdf.multi_cell(0, 6, line[3:])
            continue
        if line.startswith("### "):
            pdf.set_font("Helvetica", "B", 11)
            pdf.multi_cell(0, 6, line[4:])
            continue
        if line.startswith("|") or line.startswith("```"):
            pdf.set_font("Courier", "", 8)
            pdf.multi_cell(0, 4, line[:100])
            continue
        pdf.set_font("Helvetica", "", 10)
        pdf.multi_cell(0, 5, line)

    OUT_DOC.parent.mkdir(parents=True, exist_ok=True)
    OUT_WEB.parent.mkdir(parents=True, exist_ok=True)
    pdf.output(str(OUT_DOC))
    OUT_WEB.write_bytes(OUT_DOC.read_bytes())
    print(f"Built: {OUT_WEB} ({OUT_WEB.stat().st_size // 1024} KB)")


if __name__ == "__main__":
    main()
