"""Policy P0: identical capabilities always exposed. Belief is recorded, never acted on."""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

from cs.actors import ActorMap
from cs.tinyhttp import json_body, serve

BIND = os.environ.get("CS_BIND", "0.0.0.0")
PORT = int(os.environ.get("CS_PORT", "9000"))
SEED = Path(os.environ.get("CS_MANIFEST_SEED", "/config/manifest-p0.json"))
CURRENT = Path(os.environ.get("CS_MANIFEST_CURRENT", "/data/manifests/current.json"))

actors = ActorMap()
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
    rec = actors.resolve(event)
    rec["events"] = int(rec.get("events") or 0) + 1
    rec["last_dataset"] = event.get("event", {}).get("dataset")
    rec["last_seen"] = event.get("@timestamp")
    actor = rec["actor_key"]
    belief[actor] = rec
    # Drop stale keys that were merged away.
    for stale in [k for k in belief if k not in actors.actors]:
        belief.pop(stale, None)
    event.setdefault("session", {})["actor_key"] = actor
    event.setdefault("cybersnare", {})["linkage_confidence"] = rec.get(
        "linkage_confidence"
    )
    manifest = load_seed()
    manifest["generated_at"] = event.get("@timestamp")
    manifest["actor_key"] = actor
    manifest["linked_ips"] = rec.get("linked_ips")
    manifest["linkage_confidence"] = rec.get("linkage_confidence")
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
