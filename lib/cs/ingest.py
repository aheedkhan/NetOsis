"""Fire-and-forget ingest to the logger hub on the mgmt network."""

from __future__ import annotations

import asyncio
import os
from typing import Any

from cs.tinyhttp import post_json

LOGGER_HOST = os.environ.get("CS_LOGGER_HOST", "10.200.1.10")
LOGGER_PORT = int(os.environ.get("CS_LOGGER_PORT", "8088"))


async def emit(event: dict[str, Any]) -> None:
    try:
        await post_json(LOGGER_HOST, LOGGER_PORT, "/v1/events", event, timeout=0.4)
    except Exception as exc:
        print(f"ingest failed: {exc}", flush=True)


def emit_bg(event: dict[str, Any]) -> None:
    asyncio.create_task(emit(event))
