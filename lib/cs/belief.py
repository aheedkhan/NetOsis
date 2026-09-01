"""Per-actor belief state — §6.2 of the design record."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Closed objective taxonomy (draft — freeze by week 2 per design record).
OBJECTIVES = (
    "recon_scan",
    "credential_spray",
    "exploit_attempt",
    "lateral_movement",
    "exfiltration",
    "unknown",
)


@dataclass
class BeliefState:
    actor_key: str
    linked_ips: list[str] = field(default_factory=list)
    hassh: str | None = None
    ja4: str | None = None
    linkage_confidence: str = "none"
    events: int = 0
    capability: str = "automated"  # automated | scripted | interactive_operator
    level: str = "L1"
    posture: str = "L1"
    engagement_depth: float = 0.0
    engagement_duration_s: float = 0.0
    novelty: float = 1.0
    suspicion: float = 0.05
    behavioural_score: float = 0.0
    intel_gain: float = 0.0
    intent: dict[str, float] = field(default_factory=dict)
    p_human: float = 0.5
    operator_confidence: float = 0.0
    operator_signals: list[dict[str, Any]] = field(default_factory=list)
    last_dataset: str | None = None
    last_seen: str | None = None
    datasets_seen: set[str] = field(default_factory=set)

    def to_dict(self) -> dict[str, Any]:
        return {
            "actor_key": self.actor_key,
            "linked_ips": self.linked_ips,
            "hassh": self.hassh,
            "ja4": self.ja4,
            "linkage_confidence": self.linkage_confidence,
            "events": self.events,
            "capability": self.capability,
            "level": self.level,
            "posture": self.posture,
            "engagement": {
                "depth": round(self.engagement_depth, 4),
                "duration_s": round(self.engagement_duration_s, 2),
            },
            "novelty": round(self.novelty, 4),
            "suspicion": round(self.suspicion, 4),
            "behavioural_score": round(self.behavioural_score, 4),
            "intel_gain": round(self.intel_gain, 4),
            "p_human": round(self.p_human, 4),
            "operator_confidence": round(self.operator_confidence, 4),
            "operator_signals": self.operator_signals,
            "intent": {k: round(v, 4) for k, v in self.intent.items()},
            "last_dataset": self.last_dataset,
            "last_seen": self.last_seen,
            "datasets_seen": sorted(self.datasets_seen),
        }


def default_intent() -> dict[str, float]:
    n = len(OBJECTIVES)
    base = 1.0 / n
    return {obj: base for obj in OBJECTIVES}


def belief_from_actor_rec(rec: dict[str, Any]) -> BeliefState:
    return BeliefState(
        actor_key=rec["actor_key"],
        linked_ips=list(rec.get("linked_ips") or []),
        hassh=rec.get("hassh"),
        ja4=rec.get("ja4"),
        linkage_confidence=rec.get("linkage_confidence") or "none",
        events=int(rec.get("events") or 0),
        capability=rec.get("capability") or "automated",
        level=rec.get("level") or "L1",
        posture=rec.get("posture") or rec.get("level") or "L1",
        engagement_depth=float(rec.get("engagement_depth") or 0.0),
        engagement_duration_s=float(rec.get("engagement_duration_s") or 0.0),
        novelty=float(rec.get("novelty") if rec.get("novelty") is not None else 1.0),
        suspicion=float(rec.get("suspicion") if rec.get("suspicion") is not None else 0.05),
        behavioural_score=float(rec.get("behavioural_score") or 0.0),
        intel_gain=float(rec.get("intel_gain") or 0.0),
        p_human=float(rec.get("p_human") if rec.get("p_human") is not None else 0.5),
        operator_confidence=float(rec.get("operator_confidence") or 0.0),
        operator_signals=list(rec.get("operator_signals") or []),
        intent=dict(rec.get("intent") or default_intent()),
        last_dataset=rec.get("last_dataset"),
        last_seen=rec.get("last_seen"),
        datasets_seen=set(rec.get("datasets_seen") or []),
    )


def sync_belief_to_rec(belief: BeliefState, rec: dict[str, Any]) -> None:
    rec.update(
        {
            "capability": belief.capability,
            "level": belief.level,
            "posture": belief.posture,
            "engagement_depth": belief.engagement_depth,
            "engagement_duration_s": belief.engagement_duration_s,
            "novelty": belief.novelty,
            "suspicion": belief.suspicion,
            "behavioural_score": belief.behavioural_score,
            "intel_gain": belief.intel_gain,
            "p_human": belief.p_human,
            "operator_confidence": belief.operator_confidence,
            "operator_signals": belief.operator_signals,
            "intent": belief.intent,
            "datasets_seen": sorted(belief.datasets_seen),
        }
    )
