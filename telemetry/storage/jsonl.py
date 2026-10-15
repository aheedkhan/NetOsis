from __future__ import annotations

import json
import threading
from pathlib import Path

from telemetry.schema.events import TelemetryEvent


_WRITE_LOCK = threading.Lock()


class JsonlTelemetryStore:
    """Append-only JSONL telemetry store (raw events)."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, event: TelemetryEvent) -> None:
        line = json.dumps(event.to_dict(), ensure_ascii=False) + "\n"
        with _WRITE_LOCK, self.path.open("a", encoding="utf-8") as fh:
            fh.write(line)

    def read_all(self) -> list[dict]:
        if not self.path.exists():
            return []
        events: list[dict] = []
        with self.path.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    events.append(json.loads(line))
        return events
