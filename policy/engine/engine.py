from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_RULES = ROOT / "policy" / "rules" / "baseline.yml"


@dataclass
class PolicyDecision:
    action: str | None
    action_name: str | None
    risk_score: float
    level: str
    reason: str


@lru_cache(maxsize=4)
def _load_rules(path_str: str) -> dict[str, Any]:
    with Path(path_str).open(encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def score_events(events: list[dict[str, Any]], rules_path: str | Path | None = None) -> float:
    path = Path(rules_path) if rules_path else DEFAULT_RULES
    rules = _load_rules(str(path))
    weights: dict[str, float] = {k: float(v) for k, v in (rules.get("weights") or {}).items()}
    total = 0.0
    seen: set[str] = set()
    for event in events:
        # Prefer explicit category from mapper path via behavior heuristics
        category = event.get("risk_category")
        if not category:
            # Fallback from technique families used in slice
            tech = event.get("technique")
            if tech in {"T1033", "T1083"}:
                category = "Discovery"
            elif tech == "T1005":
                category = "Collection"
            else:
                category = None
        if not category:
            continue
        key = f"{category}:{event.get('command')}"
        if key in seen:
            continue
        seen.add(key)
        total += weights.get(category, 0.0)
    return total


def risk_level(score: float) -> str:
    if score >= 12:
        return "CRITICAL"
    if score >= 8:
        return "HIGH"
    if score >= 3:
        return "MEDIUM"
    return "LOW"


def evaluate(
    events: list[dict[str, Any]],
    already_triggered: set[str] | None = None,
    rules_path: str | Path | None = None,
) -> PolicyDecision:
    path = Path(rules_path) if rules_path else DEFAULT_RULES
    rules = _load_rules(str(path))
    score = score_events(events, path)
    level = risk_level(score)
    triggered = already_triggered or set()
    threshold = float(rules.get("d01_threshold", 3))
    actions = rules.get("actions") or {}

    if "D01" not in triggered and score >= threshold:
        meta = actions.get("D01") or {}
        return PolicyDecision(
            action="D01",
            action_name=str(meta.get("name", "expose_fake_host")),
            risk_score=score,
            level=level,
            reason=f"score {score} >= D01 threshold {threshold}",
        )

    return PolicyDecision(
        action=None,
        action_name=None,
        risk_score=score,
        level=level,
        reason="no new deception action",
    )
