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
                    # Operator classification — computed in lib/cs/operator.py,
                    # carried on the belief state, but otherwise never reaches
                    # the JSONL system of record. Without this the intelligence
                    # plane cannot show bot-vs-human at all, since it reads only
                    # the event log, not decision's live in-memory state.
                    "capability": belief.get("capability"),
                    "p_human": belief.get("p_human"),
                    "operator_confidence": belief.get("operator_confidence"),
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
