from __future__ import annotations

import re
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
    entries = list(data.get("mappings") or [])
    for entry in entries:
        # Compile once; a bad pattern in YAML must never crash a live session.
        compiled = []
        for pat in entry.get("patterns") or []:
            try:
                compiled.append(re.compile(pat, re.I))
            except re.error:
                continue
        entry["_compiled"] = compiled
    return entries


def _result(entry: dict[str, Any]) -> MappingResult:
    return MappingResult(
        behavior=str(entry["behavior"]),
        technique=str(entry["technique"]),
        technique_name=str(entry["technique_name"]),
        confidence=float(entry.get("confidence", 0.5)),
        risk_category=str(entry.get("risk_category", "Discovery")),
    )


def _first_command(command: str) -> str:
    """First real command word — skips `sudo` and leading VAR=value."""
    words = command.strip().split()
    while words and (words[0] == "sudo" or re.fullmatch(r"\w+=\S*", words[0])):
        words = words[1:]
    return words[0].rsplit("/", 1)[-1].lower() if words else ""


def map_command(command: str, mappings_path: str | Path | None = None) -> MappingResult | None:
    """Map a shell command to an ATT&CK technique with confidence.

    Entries with `patterns` match the whole line (e.g. `cat /etc/shadow` is
    credential access, plain `cat notes.txt` is local-data collection) and are
    tried first; plain `commands` entries match the first command word.
    """
    line = command.strip()
    if not line:
        return None
    path = Path(mappings_path) if mappings_path else DEFAULT_MAPPINGS
    entries = _load_mappings(str(path))
    for entry in entries:
        if any(rx.search(line) for rx in entry["_compiled"]):
            return _result(entry)
    cmd = _first_command(line)
    for entry in entries:
        if cmd in [c.lower() for c in entry.get("commands") or []]:
            return _result(entry)
    return None
