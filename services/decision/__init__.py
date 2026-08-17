"""Policy P0: identical capabilities always exposed. Belief is recorded, never acted on."""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

from cs.tinyhttp import json_body, serve

BIND = os.environ.get("CS_BIND", "0.0.0.0")
PORT = int(os.environ.get("CS_PORT", "9000"))
SEED = Path(os.environ.get("CS_MANIFEST_SEED", "/config/manifest-p0.json"))
CURRENT = Path(os.environ.get("CS_MANIFEST_CURRENT", "/data/manifests/current.json"))

belief: dict[str, dict] = {}
last_event: dict | None = None
seen = 0


def load_seed() -> dict:
    with SEED.open(encoding="utf-8") as fh:
        return json.load(fh)


def persist(manifest: dict) -> None:
    CURRENT.parent.mkdir(parents=True, exist_ok=True)
    tmp = CURRENT.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    tmp.replace(CURRENT)


def apply_p0(event: dict) -> dict:
    global last_event, seen
    seen += 1
    last_event = event
    actor = event.get("session", {}).get("actor_key", "actor:unknown")
    slot = belief.setdefault(
        actor,
        {
            "actor_key": actor,
            "events": 0,
            "capability": "unknown",
            "intent": None,
            "level": "L1",
        },
    )
    slot["events"] += 1
    slot["last_dataset"] = event.get("event", {}).get("dataset")
    slot["last_seen"] = event.get("@timestamp")
    manifest = load_seed()
    manifest["generated_at"] = event.get("@timestamp")
    manifest["actor_key"] = actor
    manifest["events_seen"] = seen
    persist(manifest)
    return manifest


async def handler(req: dict) -> tuple[int, dict[str, str], bytes]:
    path, method = req["path"], req["method"]
    if method == "GET" and path == "/health":
        body = json.dumps(
            {"ok": True, "policy": "P0", "actors": len(belief), "events_seen": seen}
        ).encode()
        return 200, {"Content-Type": "application/json"}, body
    if method == "GET" and path == "/v1/manifest":
        if CURRENT.exists():
            return 200, {"Content-Type": "application/json"}, CURRENT.read_bytes()
        return 200, {"Content-Type": "application/json"}, json.dumps(load_seed()).encode()
    if method == "GET" and path == "/v1/belief":
        return 200, {"Content-Type": "application/json"}, json.dumps(
            {"actors": belief}
        ).encode()
    if method == "POST" and path == "/v1/event":
        try:
            event = json_body(req)
        except Exception:
            return 400, {"Content-Type": "text/plain"}, b"invalid json\n"
        if not isinstance(event, dict):
            return 400, {"Content-Type": "text/plain"}, b"invalid event\n"
        apply_p0(event)
        return 204, {}, b""
    return 404, {"Content-Type": "text/plain"}, b"not found\n"


async def main() -> None:
    persist(load_seed())
    server = await serve(BIND, PORT, handler, name="decision")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
