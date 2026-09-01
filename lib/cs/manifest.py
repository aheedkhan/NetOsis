"""Poll decision plane manifest — actuators reconcile to this."""

from __future__ import annotations

import asyncio
import json
import os
import urllib.request
from typing import Any

DEFAULT = {
    "manifest_id": "p0-static-v1",
    "policy": "P0",
    "level": "L1",
    "capabilities": {
        "ssh": {"exposed": True, "auth": "closed"},
        "http": {"exposed": False, "auth": "closed"},
        "https": {"exposed": True, "auth": "closed"},
        "shell": {"exposed": False},
    },
}

_state: dict[str, Any] = dict(DEFAULT)
_lock = asyncio.Lock()


def get() -> dict[str, Any]:
    return _state


def capability(name: str) -> dict[str, Any]:
    return (_state.get("capabilities") or {}).get(name) or {}


def auth_mode(cap: str) -> str:
    return str(capability(cap).get("auth") or "closed")


def is_exposed(cap: str) -> bool:
    return bool(capability(cap).get("exposed", True))


def level() -> str:
    return str(_state.get("level") or "L1")


def manifest_id() -> str:
    return str(_state.get("manifest_id") or "p0-static-v1")


def _fetch(host: str, port: int) -> dict[str, Any]:
    url = f"http://{host}:{port}/v1/manifest"
    raw = urllib.request.urlopen(url, timeout=3).read()
    data = json.loads(raw)
    return data if isinstance(data, dict) else DEFAULT


async def poll_forever(
    host: str | None = None,
    port: int | None = None,
    interval: float | None = None,
) -> None:
    host = host or os.environ.get("CS_DECISION_HOST", "10.200.1.11")
    port = port or int(os.environ.get("CS_DECISION_PORT", "9000"))
    interval = interval or float(os.environ.get("CS_MANIFEST_POLL", "2.0"))

    while True:
        try:
            data = await asyncio.to_thread(_fetch, host, port)
            async with _lock:
                _state.clear()
                _state.update(data)
        except Exception:
            pass
        await asyncio.sleep(interval)


async def wait_ready(host: str | None = None, port: int | None = None) -> None:
    host = host or os.environ.get("CS_DECISION_HOST", "10.200.1.11")
    port = port or int(os.environ.get("CS_DECISION_PORT", "9000"))
    for _ in range(60):
        try:
            data = await asyncio.to_thread(_fetch, host, port)
            async with _lock:
                _state.clear()
                _state.update(data)
            return
        except Exception:
            await asyncio.sleep(0.5)
    raise RuntimeError("decision manifest not available")
