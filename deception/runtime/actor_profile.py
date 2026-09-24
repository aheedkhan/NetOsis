from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ActorProfile:
    """Lightweight behavioral profile for an attacker session (explainable)."""

    actor_id: str
    source_ip: str
    commands: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    behaviors: list[str] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    canary_hits: int = 0
    risk_score: float = 0.0
    level: str = "LOW"

    def observe(self, event: dict[str, Any], risk_score: float, level: str) -> None:
        cmd = event.get("command")
        if cmd:
            self.commands.append(str(cmd))
        tech = event.get("technique")
        if tech and tech not in self.techniques:
            self.techniques.append(str(tech))
        behavior = event.get("behavior")
        if behavior and behavior not in self.behaviors:
            self.behaviors.append(str(behavior))
        category = event.get("risk_category")
        if category and category not in self.categories:
            self.categories.append(str(category))
        if category == "Canary_interaction":
            self.canary_hits += 1
        self.risk_score = risk_score
        self.level = level

    def summary(self) -> dict[str, Any]:
        return {
            "actor_id": self.actor_id,
            "source_ip": self.source_ip,
            "command_count": len(self.commands),
            "techniques": list(self.techniques),
            "behaviors": list(self.behaviors),
            "categories": list(self.categories),
            "canary_hits": self.canary_hits,
            "risk_score": self.risk_score,
            "level": self.level,
        }
