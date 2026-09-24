from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MAPPINGS = ROOT / "mitre" / "mappings" / "command_behaviors.yml"


@dataclass
class MappingResult:
    behavior: str
    technique: str
    technique_name: str
    confidence: float
    risk_category: str


@lru_cache(maxsize=4)
def _load_mappings(path_str: str) -> list[dict[str, Any]]:
    path = Path(path_str)
    with path.open(encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    return list(data.get("mappings") or [])


def map_command(command: str, mappings_path: str | Path | None = None) -> MappingResult | None:
    """Map a shell command basename to ATT&CK technique with confidence."""
    cmd = command.strip().split()[0] if command.strip() else ""
    if not cmd:
        return None
    path = Path(mappings_path) if mappings_path else DEFAULT_MAPPINGS
    for entry in _load_mappings(str(path)):
        commands = [c.lower() for c in entry.get("commands") or []]
        if cmd.lower() in commands:
            return MappingResult(
                behavior=str(entry["behavior"]),
                technique=str(entry["technique"]),
                technique_name=str(entry["technique_name"]),
                confidence=float(entry.get("confidence", 0.5)),
                risk_category=str(entry.get("risk_category", "Discovery")),
            )
    return None
