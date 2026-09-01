"""Slow-path intent worker — tails JSONL, never on the attacker request path."""

from __future__ import annotations

import json
import os
import time
import urllib.request
from collections import defaultdict
from pathlib import Path

from cs.intent import infer_intent_slow

LOG_PATH = Path(os.environ.get("CS_LOG_PATH", "/data/events.jsonl"))
DECISION_HOST = os.environ.get("CS_DECISION_HOST", "10.200.1.11")
DECISION_PORT = int(os.environ.get("CS_DECISION_PORT", "9000"))
INTERVAL = float(os.environ.get("CS_INTENT_INTERVAL", "5"))


def _load_events() -> list[dict]:
    if not LOG_PATH.exists():
        return []
    lines = LOG_PATH.read_text(encoding="utf-8", errors="replace").splitlines()
    out: list[dict] = []
    for line in lines[-500:]:
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def _group_by_actor(events: list[dict]) -> dict[str, list[dict]]:
    groups: dict[str, list[dict]] = defaultdict(list)
    for ev in events:
        session = ev.get("session") or {}
        key = session.get("actor_key")
        if key:
            groups[key].append(ev)
    return groups


def _post_intent(actor_key: str, result: dict) -> None:
    url = f"http://{DECISION_HOST}:{DECISION_PORT}/v1/intent/{actor_key}"
    data = json.dumps(result).encode()
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        urllib.request.urlopen(req, timeout=2)
    except OSError:
        pass


def main() -> None:
    seen: dict[str, str] = {}
    print("intent-worker: slow path online", flush=True)
    while True:
        for actor, evs in _group_by_actor(_load_events()).items():
            sig = f"{len(evs)}:{evs[-1].get('@timestamp')}"
            if seen.get(actor) == sig:
                continue
            seen[actor] = sig
            result = infer_intent_slow(evs)
            _post_intent(actor, result)
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
