from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class TelemetryEvent:
    timestamp: str
    session_id: str
    actor_id: str
    source_ip: str
    target_host: str
    target_ip: str
    event_type: str
    command: str
    result: str
    virtual: bool = True
    technique: str | None = None
    technique_name: str | None = None
    technique_confidence: float = 0.0
    behavior: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        if not data["extra"]:
            data.pop("extra")
        return data
