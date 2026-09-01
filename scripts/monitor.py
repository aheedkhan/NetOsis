#!/usr/bin/env python3
"""Live activity monitor — dynamic deception vs static honeypots."""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.request

from cs.activity import format_monitor

DECISION = os.environ.get("CS_DECISION_URL", "http://127.0.0.1:19000")
LOGGER = os.environ.get("CS_LOGGER_URL", "http://127.0.0.1:18088")
INTERVAL = float(os.environ.get("CS_MONITOR_INTERVAL", "2"))


def _get(url: str) -> dict:
    raw = urllib.request.urlopen(url, timeout=3).read()
    return json.loads(raw)


def main() -> int:
    once = "--once" in sys.argv
    try:
        while True:
            if not once:
                print("\033[2J\033[H", end="")
            try:
                activity = _get(f"{DECISION}/v1/activity")
                tail = _get(f"{LOGGER}/v1/tail?n=12")
            except OSError as exc:
                print(f"CyberSnare monitor: cannot reach stack ({exc})")
                print("Start lab: ./cs up")
                return 1
            print(
                format_monitor(
                    policy=activity.get("policy", "?"),
                    manifest=activity.get("manifest") or {},
                    actors=activity.get("actors") or [],
                    transitions=activity.get("transitions") or [],
                    recent=tail.get("lines") or [],
                )
            )
            if once:
                return 0
            print(f"\n Refreshing every {INTERVAL:.0f}s — Ctrl+C to stop")
            time.sleep(INTERVAL)
    except KeyboardInterrupt:
        print("\nMonitor stopped.")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
