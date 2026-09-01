#!/usr/bin/env python3
"""Milestone 1 analysis — arm comparison from JSONL (P5 entry point)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from cs.intelligence import load_events, milestone_report  # noqa: E402


def main() -> int:
    log = Path(sys.argv[1] if len(sys.argv) > 1 else ROOT / "data/events/events.jsonl")
    events = load_events(log)
    report = milestone_report(events)
    out = ROOT / "data/milestone1-report.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    print(f"\nWritten: {out}", file=sys.stderr)
    arms = report.get("arms") or {}
    if len(arms) < 2:
        print(
            "\nNote: run all three arms and ./cs redteam to populate comparative data.",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
