"""Canonical event envelope. This is the integration contract."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

REQUIRED = (
    "@timestamp",
    "event",
    "session",
    "source",
    "destination",
    "network",
    "user",
    "threat",
    "deception",
    "cybersnare",
)

ARM = os.environ.get("CS_ARM", "A")
LEVEL = os.environ.get("CS_LEVEL", "L1")
MANIFEST_ID = os.environ.get("CS_MANIFEST_ID", "p0-static-v1")


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def actor_key_from_ip(ip: str | None) -> str:
    """v0 linkage: address only. Zeek HASSH/JA4 replace this in P1."""
    if not ip:
        return "actor:unknown"
    return f"ip:{ip}"


def new_event(
    *,
    dataset: str,
    action: str,
    category: list[str],
    capability: str,
    source_ip: str | None = None,
    source_port: int | None = None,
    dest_ip: str | None = None,
    dest_port: int | None = None,
    dest_service: str | None = None,
    session_id: str | None = None,
    actor_key: str | None = None,
    user_name: str | None = None,
    hassh: str | None = None,
    ja4: str | None = None,
    ua_signature: str | None = None,
    technique_id: str | None = None,
    technique_name: str | None = None,
    tactic_id: str | None = None,
    tactic_name: str | None = None,
    engage_activity: str | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    event: dict[str, Any] = {
        "@timestamp": utcnow(),
        "event": {
            "kind": "event",
            "category": category,
            "action": action,
            "dataset": dataset,
        },
        "session": {
            "id": session_id,
            "actor_key": actor_key or actor_key_from_ip(source_ip),
            "arm": ARM,
            "level": LEVEL,
        },
        "source": {"ip": source_ip, "port": source_port},
        "destination": {
            "ip": dest_ip,
            "port": dest_port,
            "service": dest_service,
        },
        "network": {
            "hassh": hassh,
            "ja4": ja4,
            "ua_signature": ua_signature,
        },
        "user": {"name": user_name},
        "threat": {
            "technique": {"id": technique_id, "name": technique_name},
            "tactic": {"id": tactic_id, "name": tactic_name},
        },
        "deception": {
            "capability": capability,
            "manifest_id": MANIFEST_ID,
            "engage_activity": engage_activity,
        },
        "cybersnare": {
            "score_delta": None,
            "intent": None,
            "confidence": None,
            "suspicion": None,
            "novelty": None,
        },
    }
    if extra:
        event.update(extra)
    return event


def validate(event: dict[str, Any]) -> list[str]:
    missing = [k for k in REQUIRED if k not in event]
    return [f"missing:{k}" for k in missing]
