"""Policy modules — P0 static, P1 utility, P2 intent-conditioned."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

from cs.belief import BeliefState, default_intent, sync_belief_to_rec
from cs.operator import OperatorAssessment
from cs.scoring import pick_level_p1, pick_level_p2, update_belief_from_event

MANIFEST_BY_LEVEL = {
    "L0": "manifest-l0.json",
    "L1": "manifest-l1.json",
    "L2": "manifest-l2.json",
    "L3": "manifest-l3.json",
    "BURN": "manifest-burn.json",
    "BLOCK": "manifest-block.json",
}

_LEVEL_RANK = {"L0": 0, "L1": 1, "L2": 2, "L3": 3, "BURN": 4, "BLOCK": 5}


def apply_operator_gate(
    level: str,
    assessment: OperatorAssessment | None,
) -> tuple[str, str | None]:
    """
    Capability gate — the resource rule.

    Deception is only spent on actors that can appreciate it. An automated tool
    is dropped at the boundary; a script is served the cheap L1 surface and
    nothing more; only an actor that looks like a person in the loop is allowed
    to reach the levels that cost something to run.

    This is deliberately applied AFTER the policy has chosen a level rather than
    inside it. The policy answers "how much engagement does the evidence
    justify"; the gate answers "is there anybody there to engage". Keeping them
    separate means the gate can be disabled for the control arm without
    touching policy code, which is what makes the comparison clean.
    """
    if assessment is None:
        return level, None

    if assessment.should_block:
        return "BLOCK", (
            f"automated actor (p_human={assessment.p_human:.2f}, "
            f"confidence={assessment.confidence:.2f}) — dropped at the perimeter "
            f"rather than served"
        )

    if assessment.capability == "scripted" and _LEVEL_RANK.get(level, 1) > 1:
        return "L1", (
            f"scripted actor (p_human={assessment.p_human:.2f}) — held at L1; "
            f"escalation to {level} withheld until a human operator is evident"
        )

    if (
        assessment.capability == "automated"
        and _LEVEL_RANK.get(level, 1) > 1
    ):
        # Automated but not confidently enough to drop. Do not spend an
        # expensive surface on it either.
        return "L1", (
            f"probable automation (p_human={assessment.p_human:.2f}, "
            f"confidence={assessment.confidence:.2f}) — held at L1"
        )

    return level, None


def load_manifest(config_dir: Path, name: str) -> dict[str, Any]:
    path = config_dir / name
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def _apply_level(manifest: dict[str, Any], level: str) -> dict[str, Any]:
    out = deepcopy(manifest)
    out["level"] = level
    caps = out.get("capabilities") or {}

    if level == "L0":
        for key in ("ssh", "http", "https"):
            if key in caps:
                caps[key]["exposed"] = False
    elif level == "L1":
        if "shell" in caps:
            caps["shell"]["exposed"] = False
            caps["shell"]["reason"] = "L1 attract: authentication closed."
    elif level == "L2":
        if "shell" in caps:
            caps["shell"]["exposed"] = True
            caps["shell"].pop("reason", None)
    elif level == "L3":
        if "shell" in caps:
            caps["shell"]["exposed"] = True
        if "internal_net" in caps:
            caps["internal_net"]["exposed"] = True
    elif level == "BURN":
        for key in ("ssh", "http", "https", "shell", "internal_net"):
            if key in caps:
                caps[key]["exposed"] = False
        out["rationale"] = "BURN: suspicion high — freeze capabilities, harvest evidence."
    return out


class PolicyEngine:
    def __init__(self, config_dir: Path, policy: str = "P0") -> None:
        self.config_dir = config_dir
        self.policy = policy.upper()
        self._cache: dict[str, dict[str, Any]] = {}

    def _base(self, level: str) -> dict[str, Any]:
        fname = MANIFEST_BY_LEVEL.get(level, "manifest-l1.json")
        if fname not in self._cache:
            self._cache[fname] = load_manifest(self.config_dir, fname)
        return deepcopy(self._cache[fname])

    def evaluate(
        self,
        belief: BeliefState,
        event: dict[str, Any],
        actor_rec: dict[str, Any],
        assessment: OperatorAssessment | None = None,
    ) -> dict[str, Any]:
        update_belief_from_event(belief, event)
        if not belief.intent:
            belief.intent = default_intent()

        gate_reason: str | None = None

        if self.policy == "P0":
            # Arm A is the static control. The operator gate is part of the
            # treatment, so it is deliberately not applied here — otherwise the
            # control arm would adapt and the comparison would measure nothing.
            level = "L1"
            p0 = self.config_dir / "manifest-p0.json"
            manifest = (
                load_manifest(self.config_dir, "manifest-p0.json")
                if p0.exists()
                else self._base("L1")
            )
            manifest = deepcopy(manifest)
            manifest["policy"] = "P0"
            manifest["arm"] = "A"
        elif self.policy == "P1":
            level = pick_level_p1(belief)
            level, gate_reason = apply_operator_gate(level, assessment)
            manifest = _apply_level(self._base(level if level in MANIFEST_BY_LEVEL else "L1"), level)
            manifest["policy"] = "P1"
            manifest["arm"] = "B"
        elif self.policy == "P2":
            level = pick_level_p2(belief)
            level, gate_reason = apply_operator_gate(level, assessment)
            manifest = _apply_level(self._base(level if level in MANIFEST_BY_LEVEL else "L1"), level)
            manifest["policy"] = "P2"
            manifest["arm"] = "C"
        else:
            level = "L1"
            manifest = self._base("L1")
            manifest["policy"] = self.policy

        belief.posture = level
        belief.level = level
        sync_belief_to_rec(belief, actor_rec)

        manifest["generated_at"] = event.get("@timestamp")
        manifest["actor_key"] = belief.actor_key
        manifest["linked_ips"] = belief.linked_ips
        manifest["linkage_confidence"] = belief.linkage_confidence
        manifest["belief"] = {
            "behavioural_score": belief.behavioural_score,
            "intel_gain": belief.intel_gain,
            "suspicion": belief.suspicion,
            "novelty": belief.novelty,
            "intent": belief.intent,
            "capability": belief.capability,
            "p_human": belief.p_human,
            "operator_confidence": belief.operator_confidence,
            "level": level,
        }
        if assessment is not None:
            manifest["operator"] = assessment.to_dict()
        if gate_reason:
            manifest["gate"] = {"applied": True, "reason": gate_reason}
        if self.policy in ("P1", "P2"):
            top = max(belief.intent, key=belief.intent.get) if belief.intent else "unknown"
            manifest["rationale"] = (
                f"{self.policy}: level {level} for actor — "
                f"score={belief.behavioural_score:.2f}, intent={top}, "
                f"suspicion={belief.suspicion:.2f}"
            )
            if gate_reason:
                manifest["rationale"] += f" | gate: {gate_reason}"
        return manifest
