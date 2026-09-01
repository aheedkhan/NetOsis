"""Behavioural feature extraction and P1 utility scoring — evidence, not the sole decision."""

from __future__ import annotations

from typing import Any

from cs.belief import OBJECTIVES, BeliefState, default_intent

# Dataset → objective hint weights (deterministic fast path, no LLM).
_DATASET_HINTS: dict[str, dict[str, float]] = {
    "cybersnare.zeek.conn": {"recon_scan": 0.6, "unknown": 0.4},
    "cybersnare.zeek.ssh": {"credential_spray": 0.5, "recon_scan": 0.3, "unknown": 0.2},
    "cybersnare.zeek.ssl": {"recon_scan": 0.4, "unknown": 0.6},
    "cybersnare.zeek.http": {"recon_scan": 0.5, "unknown": 0.5},
    "cybersnare.http.request": {"credential_spray": 0.7, "recon_scan": 0.2, "unknown": 0.1},
    "cybersnare.ssh.auth": {"credential_spray": 0.8, "exploit_attempt": 0.1, "unknown": 0.1},
    "cybersnare.sinkhole.dns": {"exfiltration": 0.4, "lateral_movement": 0.3, "unknown": 0.3},
    "cybersnare.sinkhole.http": {"exfiltration": 0.5, "lateral_movement": 0.3, "unknown": 0.2},
}

_SUSPICION_DATASETS = frozenset(
    {
        "cybersnare.shell.proc_read",
        "cybersnare.shell.dmesg_read",
        "cybersnare.shell.vm_check",
    }
)


def _dataset(event: dict[str, Any]) -> str:
    return (event.get("event") or {}).get("dataset") or ""


def _level_rank(level: str) -> int:
    return {"L0": 0, "L1": 1, "L2": 2, "L3": 3, "BURN": 4, "BLOCK": 5}.get(level, 1)


def update_belief_from_event(belief: BeliefState, event: dict[str, Any]) -> None:
    ds = _dataset(event)
    belief.events += 1
    belief.last_dataset = ds
    belief.last_seen = event.get("@timestamp")
    if ds:
        belief.datasets_seen.add(ds)

    # Engagement depth: unique datasets and interactive signals.
    belief.engagement_depth = min(1.0, len(belief.datasets_seen) / 8.0)

    # Novelty decays as datasets repeat.
    if ds and belief.events > 1:
        belief.novelty = max(0.05, belief.novelty * 0.97)

    # Capability is deliberately NOT set here. It is owned by cs.operator,
    # which reasons over the whole session rather than the current event. The
    # rules that used to live here — a fingerprint plus five events means
    # "scripted", any shell command means "interactive_operator" — ran after
    # the classifier and silently overwrote it, so a session scoring
    # p_human=0.82 was still labelled scripted. One concept, one owner.

    # Suspicion from fingerprinting probes (Flow D).
    if ds in _SUSPICION_DATASETS:
        belief.suspicion = min(1.0, belief.suspicion + 0.25)

    # Intent hints from dataset (fast deterministic path).
    hints = _DATASET_HINTS.get(ds)
    if hints:
        alpha = 0.15
        for obj in OBJECTIVES:
            target = hints.get(obj, 0.0)
            belief.intent[obj] = (1 - alpha) * belief.intent.get(
                obj, 1.0 / len(OBJECTIVES)
            ) + alpha * target
        _normalize_intent(belief.intent)

    session = event.get("session") or {}
    if session.get("level"):
        belief.level = session["level"]

    belief.behavioural_score = compute_behavioural_score(belief)


def _normalize_intent(intent: dict[str, float]) -> None:
    total = sum(intent.values()) or 1.0
    for k in list(intent.keys()):
        intent[k] = intent[k] / total


def compute_behavioural_score(belief: BeliefState) -> float:
    """Scalar evidence feature — one input to P1 utility, not a threshold."""
    fp_bonus = 0.0
    if belief.hassh:
        fp_bonus += 0.15
    if belief.ja4:
        fp_bonus += 0.10
    conf_bonus = {"high": 0.2, "medium": 0.1, "low": 0.05}.get(
        belief.linkage_confidence, 0.0
    )
    return min(
        1.0,
        0.35 * belief.engagement_depth
        + 0.25 * belief.novelty
        + 0.15 * min(1.0, belief.events / 50.0)
        + fp_bonus
        + conf_bonus,
    )


# How much weight a trained model's opinion carries against the belief state
# already accumulated from direct observation. Well under half on purpose: the
# model is a smoothed version of the pattern rules, so it should adjust the
# belief rather than replace it.
GNN_WEIGHT = 0.35


def apply_gnn_scores(belief: BeliefState, gnn: dict[str, Any]) -> None:
    """
    Merge graph-model output into the belief state.

    Two rules, both learned the hard way.

    An untrained model contributes nothing. Previously a randomly initialised
    network was constructed on demand and its sigmoid outputs were treated as
    scores; combined with the max() below, that drove every actor toward BURN
    on pure noise.

    Suspicion is blended, not maxed. max() makes the merge a ratchet: any
    upward error is permanent and no later evidence can undo it. Suspicion
    decides whether to burn a deception, so it has to be able to fall again.
    """
    if not gnn or not gnn.get("trained"):
        return

    def blend(current: float, proposed: float) -> float:
        return (1.0 - GNN_WEIGHT) * current + GNN_WEIGHT * proposed

    if "intel_gain" in gnn:
        belief.intel_gain = blend(belief.intel_gain, float(gnn["intel_gain"]))
    if "suspicion" in gnn:
        belief.suspicion = min(1.0, blend(belief.suspicion, float(gnn["suspicion"])))
    if "novelty" in gnn:
        belief.novelty = blend(belief.novelty, float(gnn["novelty"]))

    intent = gnn.get("intent")
    if isinstance(intent, dict) and intent:
        for obj in OBJECTIVES:
            if obj in intent:
                belief.intent[obj] = blend(
                    belief.intent.get(obj, 1.0 / len(OBJECTIVES)), float(intent[obj])
                )
        _normalize_intent(belief.intent)
    belief.behavioural_score = compute_behavioural_score(belief)


def apply_pattern_scores(belief: BeliefState, pattern_score: dict[str, Any]) -> None:
    """
    Fold matched attack patterns into the belief state.

    Patterns are the strongest evidence the system has about intent because they
    are the only signal that considers order. They are weighted by coverage —
    how much rule evidence actually stood behind the match — so a single
    low-confidence match nudges the belief while a corroborated one dominates.
    """
    coverage = float(pattern_score.get("coverage") or 0.0)
    if coverage <= 0.0:
        return

    weight = min(0.7, coverage)
    intent = pattern_score.get("intent") or {}
    for obj in OBJECTIVES:
        if obj in intent:
            belief.intent[obj] = (1.0 - weight) * belief.intent.get(
                obj, 1.0 / len(OBJECTIVES)
            ) + weight * float(intent[obj])
    _normalize_intent(belief.intent)

    belief.intel_gain = max(belief.intel_gain, float(pattern_score.get("intel_gain") or 0.0))
    suspicion = float(pattern_score.get("suspicion") or 0.0)
    if suspicion > 0:
        belief.suspicion = min(1.0, max(belief.suspicion, suspicion))
    belief.behavioural_score = compute_behavioural_score(belief)


def utility_p1(belief: BeliefState, *, cost_l2: float = 0.35, cost_l3: float = 0.65) -> dict[str, float]:
    """
    P1: argmax E[intel_gain] - λ·cost - μ·P(blown).
    Returns utility per candidate level.
    """
    mu = 0.8
    intel = belief.intel_gain or belief.behavioural_score
    blown = belief.suspicion
    return {
        "L0": intel * 0.2 - mu * blown * 0.1,
        "L1": intel * 0.55 - mu * blown * 0.2,
        "L2": intel * 0.85 - cost_l2 - mu * blown * 0.5,
        "L3": intel * 1.0 - cost_l3 - mu * blown * 0.85,
        "BURN": 0.15 - mu * blown * 0.05 if blown > 0.7 else -1.0,
    }


def pick_level_p1(belief: BeliefState) -> str:
    if belief.suspicion >= 0.75:
        return "BURN"
    utils = utility_p1(belief)
    best = max(
        (lvl for lvl in utils if lvl not in ("BURN",) or utils[lvl] > 0),
        key=lambda lvl: utils[lvl],
        default="L1",
    )
    if utils.get("BURN", -99) > utils.get(best, -99):
        return "BURN"
    # Dynamic escalation: enough engagement → open shell (L2) for intel yield.
    intent = belief.intent or default_intent()
    spray = intent.get("credential_spray", 0.0)
    if belief.events >= 4 and (belief.behavioural_score >= 0.28 or spray >= 0.25):
        if _level_rank("L2") > _level_rank(best):
            best = "L2"
    if belief.events >= 12 and belief.behavioural_score >= 0.5:
        if _level_rank("L3") > _level_rank(best):
            best = "L3"
    if _level_rank(best) < _level_rank(belief.posture):
        return belief.posture
    return best


def pick_level_p2(belief: BeliefState) -> str:
    """P2: manifest from inferred objective distribution."""
    if belief.suspicion >= 0.75:
        return "BURN"
    intent = belief.intent or default_intent()
    top = max(intent, key=intent.get)
    mapping = {
        "recon_scan": "L1",
        "credential_spray": "L2",
        "exploit_attempt": "L2",
        "lateral_movement": "L3",
        "exfiltration": "L3",
        "unknown": "L1",
    }
    target = mapping.get(top, "L1")
    if _level_rank(target) < _level_rank(belief.posture):
        return belief.posture
    return target
