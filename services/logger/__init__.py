"""Append-only JSONL logger. System of record. Fan-out to the decision plane."""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

from cs.events import validate
from cs.tinyhttp import json_body, serve, post_json

LOG_PATH = Path(os.environ.get("CS_LOG_PATH", "/data/events.jsonl"))
MAX_BYTES = int(os.environ.get("CS_LOG_MAX_BYTES", str(100 * 1024 * 1024)))
DECISION_HOST = os.environ.get("CS_DECISION_HOST", "10.200.1.11")
DECISION_PORT = int(os.environ.get("CS_DECISION_PORT", "9000"))
BIND = os.environ.get("CS_BIND", "0.0.0.0")
PORT = int(os.environ.get("CS_PORT", "8088"))

queue: asyncio.Queue[dict] = asyncio.Queue()
accepted = 0
dropped = 0
written = 0
forwarded = 0
forward_fail = 0


def _rotate_if_needed() -> None:
    if not LOG_PATH.exists():
        return
    if LOG_PATH.stat().st_size < MAX_BYTES:
        return
    rotated = LOG_PATH.with_suffix(".jsonl.1")
    if rotated.exists():
        rotated.unlink()
    LOG_PATH.rename(rotated)
    print(f"disk-fill guard: rotated log at {MAX_BYTES} bytes", flush=True)


async def writer() -> None:
    global written, forwarded, forward_fail, dropped
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    while True:
        event = await queue.get()
        try:
            _rotate_if_needed()
            if LOG_PATH.exists() and LOG_PATH.stat().st_size >= MAX_BYTES:
                dropped += 1
                print("disk-fill guard: refusing write", flush=True)
            else:
                with LOG_PATH.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(event, separators=(",", ":")) + "\n")
                    fh.flush()
                    os.fsync(fh.fileno())
                written += 1
            try:
                status = await post_json(
                    DECISION_HOST,
                    DECISION_PORT,
                    "/v1/event",
                    event,
                    timeout=0.1,
                )
                if 200 <= status < 300:
                    forwarded += 1
                else:
                    forward_fail += 1
            except Exception:
                forward_fail += 1
        finally:
            queue.task_done()


async def handler(req: dict) -> tuple[int, dict[str, str], bytes]:
    global accepted
    path, method = req["path"], req["method"]
    if method == "GET" and path == "/health":
        body = json.dumps(
            {
                "ok": True,
                "accepted": accepted,
                "written": written,
                "forwarded": forwarded,
                "forward_fail": forward_fail,
                "dropped": dropped,
                "queued": queue.qsize(),
            }
        ).encode()
        return 200, {"Content-Type": "application/json"}, body
    if method == "GET" and path == "/v1/tail":
        n = 20
        if "n=" in req["query"]:
            try:
                n = max(1, min(200, int(req["query"].split("n=")[1].split("&")[0])))
            except ValueError:
                n = 20
        lines: list[str] = []
        if LOG_PATH.exists():
            with LOG_PATH.open(encoding="utf-8") as fh:
                lines = fh.readlines()[-n:]
        body = json.dumps({"lines": [json.loads(x) for x in lines if x.strip()]}).encode()
        return 200, {"Content-Type": "application/json"}, body
    if method == "POST" and path == "/v1/events":
        try:
            payload = json_body(req)
        except Exception:
            return 400, {"Content-Type": "text/plain"}, b"invalid json\n"
        events = payload if isinstance(payload, list) else [payload]
        for event in events:
            if not isinstance(event, dict):
                return 400, {"Content-Type": "text/plain"}, b"invalid event\n"
            errors = validate(event)
            if errors:
                return 400, {"Content-Type": "text/plain"}, (",".join(errors) + "\n").encode()
            accepted += 1
            await queue.put(event)
        return 204, {}, b""
    return 404, {"Content-Type": "text/plain"}, b"not found\n"


async def main() -> None:
    asyncio.create_task(writer())
    server = await serve(BIND, PORT, handler, name="logger")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
