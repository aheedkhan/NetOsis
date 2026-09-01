"""Manifest transition events — auditable dynamic deception."""

from __future__ import annotations

from typing import Any

from cs.events import new_event


def transition_event(
    *,
    actor_key: str,
    from_level: str,
    to_level: str,
    policy: str,
    rationale: str,
    belief: dict[str, Any],
    trigger_dataset: str | None = None,
) -> dict[str, Any]:
    ev = new_event(
        dataset="cybersnare.decision.transition",
        action="manifest-transition",
        category=["deception", "configuration"],
        capability="decision",
        actor_key=actor_key,
        engage_activity="EAC0004",
        technique_id="T1598",
        technique_name="Phishing for Information",
        tactic_id="TA0043",
        tactic_name="Reconnaissance",
        extra={
            "decision": {
                "policy": policy,
                "from_level": from_level,
                "to_level": to_level,
                "rationale": rationale,
                "trigger_dataset": trigger_dataset,
                "belief_snapshot": {
                    "behavioural_score": belief.get("behavioural_score"),
                    "suspicion": belief.get("suspicion"),
                    "intent": belief.get("intent"),
                },
            },
        },
    )
    ev["session"]["level"] = to_level
    ev["cybersnare"] = {
        "score_delta": None,
        "intent": belief.get("intent"),
        "confidence": None,
        "suspicion": belief.get("suspicion"),
        "novelty": belief.get("novelty"),
    }
    return ev
