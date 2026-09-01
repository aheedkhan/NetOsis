"""
Attack-pattern matching over the canonical event stream.

Individual events say very little. A single blocked packet on port 445 could be
a misconfigured backup job; the same packet after a sweep of the public block
and before an authentication attempt is the middle of an intrusion. What
distinguishes them is order and proximity, so this module matches *sequences*
rather than events.

A pattern is an ordered list of steps, each of which must be satisfied by at
least one event, in order, inside a bounded window. Matching yields three
things:

  1. a named behaviour with an ATT&CK mapping, for the intelligence plane,
  2. an intent contribution, for the decision plane, and
  3. a weak label, for training the graph model.

The third is the reason this module is deliberately transparent and rule-based.
There is no labelled corpus of adversary intent for a honeypot that has not been
deployed yet, and hand-labelling one is not feasible for a project of this size.
Rules of this kind are a well-understood substitute: they are individually
imperfect but auditable, they can be written before any data exists, and their
agreement is a usable training signal. The graph model then generalises past the
rules — but the rules are what get it off the ground, and unlike the model they
can be read and argued with in a viva.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Iterable

from cs.belief import OBJECTIVES


# --------------------------------------------------------------------------
# Step and pattern definitions
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Step:
    """One required element of a sequence."""

    name: str
    datasets: tuple[str, ...] = ()
    actions: tuple[str, ...] = ()
    min_events: int = 1
    # Optional extra condition on a single event.
    predicate: Callable[[dict[str, Any]], bool] | None = None

    def matches(self, event: dict[str, Any]) -> bool:
        ds = (event.get("event") or {}).get("dataset") or ""
        action = (event.get("event") or {}).get("action") or ""
        if self.datasets and ds not in self.datasets:
            return False
        if self.actions and action not in self.actions:
            return False
        if self.predicate is not None and not self.predicate(event):
            return False
        return True


@dataclass(frozen=True)
class Pattern:
    id: str
    name: str
    description: str
    steps: tuple[Step, ...]
    window_s: float
    technique_id: str
    technique_name: str
    tactic_id: str
    tactic_name: str
    engage_activity: str
    # How much this pattern says about each objective, before normalisation.
    intent: dict[str, float] = field(default_factory=dict)
    # Contribution to expected intelligence yield, 0..1.
    intel_gain: float = 0.3
    severity: str = "medium"


@dataclass
class PatternMatch:
    pattern: Pattern
    first_seen: str | None
    last_seen: str | None
    span_s: float
    evidence: list[dict[str, Any]]
    confidence: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.pattern.id,
            "name": self.pattern.name,
            "description": self.pattern.description,
            "technique": {
                "id": self.pattern.technique_id,
                "name": self.pattern.technique_name,
            },
            "tactic": {
                "id": self.pattern.tactic_id,
                "name": self.pattern.tactic_name,
            },
            "engage_activity": self.pattern.engage_activity,
            "severity": self.pattern.severity,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "span_s": round(self.span_s, 2),
            "confidence": round(self.confidence, 3),
            "steps_matched": [e["step"] for e in self.evidence],
            "evidence": self.evidence,
        }


# --------------------------------------------------------------------------
# Predicates
# --------------------------------------------------------------------------

def _dest_zone(zone: str) -> Callable[[dict[str, Any]], bool]:
    def check(event: dict[str, Any]) -> bool:
        return (event.get("firewall") or {}).get("destination_zone") == zone
    return check


def _login_path(event: dict[str, Any]) -> bool:
    url = (event.get("url") or {}).get("path") or ""
    return any(token in url.lower() for token in ("login", "auth", "signin", "admin"))


# --------------------------------------------------------------------------
# The pattern library
# --------------------------------------------------------------------------

PATTERNS: tuple[Pattern, ...] = (
    Pattern(
        id="perimeter_sweep",
        name="Perimeter port sweep",
        description=(
            "Repeated connection attempts to ports that publish nothing, across "
            "the public address block."
        ),
        steps=(Step("blocked_probes", datasets=("cybersnare.fw.drop",), min_events=8),),
        window_s=120,
        technique_id="T1595.001",
        technique_name="Active Scanning: Scanning IP Blocks",
        tactic_id="TA0043",
        tactic_name="Reconnaissance",
        engage_activity="EAC0003",
        intent={"recon_scan": 1.0},
        intel_gain=0.15,
        severity="low",
    ),
    Pattern(
        id="service_enumeration",
        name="Published service enumeration",
        description=(
            "A sweep followed by deliberate interaction with the services that "
            "answered — the adversary is reading the estate, not just mapping it."
        ),
        steps=(
            Step("sweep", datasets=("cybersnare.fw.drop",), min_events=4),
            Step("reached_service", datasets=("cybersnare.fw.accept",), min_events=2),
            Step(
                "read_content",
                datasets=("cybersnare.http.request", "cybersnare.zeek.http"),
                min_events=2,
            ),
        ),
        window_s=600,
        technique_id="T1592",
        technique_name="Gather Victim Host Information",
        tactic_id="TA0043",
        tactic_name="Reconnaissance",
        engage_activity="EAC0003",
        intent={"recon_scan": 0.7, "exploit_attempt": 0.3},
        intel_gain=0.35,
        severity="medium",
    ),
    Pattern(
        id="credential_attack",
        name="SSH credential attack",
        description="Sustained authentication failure against the SSH surface.",
        steps=(
            Step(
                "auth_failures",
                datasets=("cybersnare.ssh.auth",),
                actions=("auth_fail", "auth_failure"),
                min_events=5,
            ),
        ),
        window_s=300,
        technique_id="T1110",
        technique_name="Brute Force",
        tactic_id="TA0006",
        tactic_name="Credential Access",
        engage_activity="EAC0005",
        intent={"credential_spray": 1.0},
        intel_gain=0.3,
        severity="medium",
    ),
    Pattern(
        id="web_login_attack",
        name="Web portal credential attack",
        description="Repeated submissions to an authentication endpoint.",
        steps=(
            Step(
                "login_attempts",
                datasets=("cybersnare.http.request",),
                min_events=5,
                predicate=_login_path,
            ),
        ),
        window_s=300,
        technique_id="T1110.003",
        technique_name="Brute Force: Password Spraying",
        tactic_id="TA0006",
        tactic_name="Credential Access",
        engage_activity="EAC0005",
        intent={"credential_spray": 1.0},
        intel_gain=0.3,
        severity="medium",
    ),
    Pattern(
        id="foothold",
        name="Interactive foothold",
        description=(
            "Authentication succeeded and commands followed — the adversary is "
            "inside the deception and using it."
        ),
        steps=(
            Step(
                "auth_success",
                datasets=("cybersnare.ssh.auth",),
                actions=("auth_success", "shell_open"),
            ),
            Step("commands", datasets=("cybersnare.shell.command",), min_events=2),
        ),
        window_s=1800,
        technique_id="T1078",
        technique_name="Valid Accounts",
        tactic_id="TA0001",
        tactic_name="Initial Access",
        engage_activity="EAC0005",
        intent={"exploit_attempt": 0.6, "lateral_movement": 0.4},
        intel_gain=0.75,
        severity="high",
    ),
    Pattern(
        id="host_discovery",
        name="Post-access host discovery",
        description="Enumeration of the host after obtaining a shell.",
        steps=(
            Step("shell", datasets=("cybersnare.shell.command",), min_events=1),
            Step(
                "discovery",
                datasets=(
                    "cybersnare.shell.proc_read",
                    "cybersnare.shell.command",
                ),
                min_events=3,
            ),
        ),
        window_s=1800,
        technique_id="T1082",
        technique_name="System Information Discovery",
        tactic_id="TA0007",
        tactic_name="Discovery",
        engage_activity="EAC0005",
        intent={"lateral_movement": 0.6, "exfiltration": 0.2, "exploit_attempt": 0.2},
        intel_gain=0.6,
        severity="high",
    ),
    Pattern(
        id="sandbox_evasion",
        name="Deception detection attempt",
        description=(
            "Probing for virtualisation and instrumentation. The adversary is "
            "checking whether the host is real, which is the signal that the "
            "deception is at risk of being burned."
        ),
        steps=(
            Step(
                "environment_checks",
                datasets=(
                    "cybersnare.shell.vm_check",
                    "cybersnare.shell.dmesg_read",
                    "cybersnare.shell.proc_read",
                ),
                min_events=2,
            ),
        ),
        window_s=900,
        technique_id="T1497",
        technique_name="Virtualization/Sandbox Evasion",
        tactic_id="TA0005",
        tactic_name="Defense Evasion",
        engage_activity="EAC0009",
        intent={"exploit_attempt": 0.5, "unknown": 0.5},
        intel_gain=0.5,
        severity="high",
    ),
    Pattern(
        id="tool_staging",
        name="Tooling retrieval",
        description=(
            "A name was resolved and then fetched — the adversary is pulling "
            "second-stage tooling. Both requests terminate at the sinkhole."
        ),
        steps=(
            Step("resolve", datasets=("cybersnare.sinkhole.dns",)),
            Step("fetch", datasets=("cybersnare.sinkhole.http",)),
        ),
        window_s=600,
        technique_id="T1105",
        technique_name="Ingress Tool Transfer",
        tactic_id="TA0011",
        tactic_name="Command and Control",
        engage_activity="EAC0003",
        intent={"exfiltration": 0.4, "lateral_movement": 0.4, "exploit_attempt": 0.2},
        intel_gain=0.85,
        severity="high",
    ),
    Pattern(
        id="lateral_movement",
        name="Internal pivot",
        description=(
            "Traffic from the deception zone toward the corporate LAN. This is "
            "the internal hop the design allows; everything it reaches is a decoy."
        ),
        steps=(
            Step(
                "internal_reach",
                datasets=("cybersnare.fw.lateral", "cybersnare.fw.lateral_denied"),
                min_events=2,
                predicate=_dest_zone("corp"),
            ),
        ),
        window_s=1800,
        technique_id="T1021",
        technique_name="Remote Services",
        tactic_id="TA0008",
        tactic_name="Lateral Movement",
        engage_activity="EAC0004",
        intent={"lateral_movement": 1.0},
        intel_gain=0.9,
        severity="critical",
    ),
    Pattern(
        id="containment_probe",
        name="Containment boundary probe",
        description=(
            "An attempt to leave the deception zone for the datacenter or the "
            "Internet. The firewall refused it. This is the highest-value "
            "observation the lab produces: it is the adversary stating an "
            "objective they could not reach."
        ),
        steps=(Step("refused", datasets=("cybersnare.fw.containment",), min_events=1),),
        window_s=3600,
        technique_id="T1048",
        technique_name="Exfiltration Over Alternative Protocol",
        tactic_id="TA0010",
        tactic_name="Exfiltration",
        engage_activity="EAC0004",
        intent={"exfiltration": 0.7, "lateral_movement": 0.3},
        intel_gain=1.0,
        severity="critical",
    ),
)

PATTERNS_BY_ID = {p.id: p for p in PATTERNS}


# --------------------------------------------------------------------------
# Matching
# --------------------------------------------------------------------------

def _ts(event: dict[str, Any]) -> float | None:
    raw = event.get("@timestamp")
    if not isinstance(raw, str):
        return None
    try:
        return datetime.strptime(raw, "%Y-%m-%dT%H:%M:%S.%f%z").timestamp()
    except ValueError:
        pass
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def match_pattern(
    pattern: Pattern, events: list[dict[str, Any]]
) -> PatternMatch | None:
    """
    Greedy in-order match.

    Steps must be satisfied in sequence: the events for step n+1 are drawn only
    from those after the last event that satisfied step n. That ordering is the
    whole point — the same set of events in a different order is a different
    behaviour, and a matcher that ignored order would collapse reconnaissance
    and exfiltration into the same finding.
    """
    ordered = sorted(
        ((e, _ts(e)) for e in events if _ts(e) is not None),
        key=lambda pair: pair[1],
    )
    if not ordered:
        return None

    cursor = 0
    evidence: list[dict[str, Any]] = []
    matched_times: list[float] = []

    for step in pattern.steps:
        hits: list[tuple[dict[str, Any], float]] = []
        index = cursor
        while index < len(ordered) and len(hits) < step.min_events:
            event, stamp = ordered[index]
            if step.matches(event):
                hits.append((event, stamp))
            index += 1
        if len(hits) < step.min_events:
            return None
        cursor = index
        first_hit, first_stamp = hits[0]
        last_hit, last_stamp = hits[-1]
        matched_times.extend([first_stamp, last_stamp])
        evidence.append(
            {
                "step": step.name,
                "count": len(hits),
                "first": first_hit.get("@timestamp"),
                "last": last_hit.get("@timestamp"),
                "sample_dataset": (first_hit.get("event") or {}).get("dataset"),
            }
        )

    span = max(matched_times) - min(matched_times)
    if span > pattern.window_s:
        return None

    # Confidence rises with how far past the minimum the evidence goes and how
    # tightly the steps cluster in time, and is capped so that no rule ever
    # claims certainty on its own.
    required = sum(s.min_events for s in pattern.steps)
    observed = sum(e["count"] for e in evidence)
    depth = min(1.0, observed / max(required, 1))
    tightness = 1.0 - min(1.0, span / pattern.window_s) if pattern.window_s else 1.0
    confidence = min(0.95, 0.45 + 0.35 * depth + 0.2 * tightness)

    first_ts = min(matched_times)
    last_ts = max(matched_times)
    return PatternMatch(
        pattern=pattern,
        first_seen=datetime.utcfromtimestamp(first_ts).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        last_seen=datetime.utcfromtimestamp(last_ts).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        span_s=span,
        evidence=evidence,
        confidence=confidence,
    )


def match_all(events: Iterable[dict[str, Any]]) -> list[PatternMatch]:
    """Every pattern satisfied by this actor's history, most severe first."""
    evs = [e for e in events if isinstance(e, dict)]
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    found = [m for m in (match_pattern(p, evs) for p in PATTERNS) if m is not None]
    return sorted(
        found, key=lambda m: (order.get(m.pattern.severity, 9), -m.confidence)
    )


# --------------------------------------------------------------------------
# Scoring — patterns as evidence for the decision plane
# --------------------------------------------------------------------------

def score(events: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """
    Turn matched patterns into the same quantities the rest of the system uses:
    an intent distribution, an expected intelligence gain, and a suspicion
    contribution.

    Intent is a confidence-weighted mixture over the matched patterns rather
    than a winner-takes-all, because two patterns matching at once is common and
    informative: a foothold plus a containment probe is a different actor from
    a foothold alone.
    """
    matches = match_all(events)
    intent = {obj: 0.0 for obj in OBJECTIVES}
    intel_gain = 0.0
    suspicion = 0.0
    total_weight = 0.0

    for match in matches:
        weight = match.confidence
        total_weight += weight
        for objective, share in match.pattern.intent.items():
            if objective in intent:
                intent[objective] += share * weight
        intel_gain = max(intel_gain, match.pattern.intel_gain * match.confidence)
        if match.pattern.id == "sandbox_evasion":
            suspicion = max(suspicion, 0.55 * match.confidence)

    if total_weight > 0:
        total = sum(intent.values()) or 1.0
        intent = {k: v / total for k, v in intent.items()}
    else:
        intent = {obj: 1.0 / len(OBJECTIVES) for obj in OBJECTIVES}

    return {
        "matches": [m.to_dict() for m in matches],
        "match_ids": [m.pattern.id for m in matches],
        "intent": intent,
        "intel_gain": intel_gain,
        "suspicion": suspicion,
        "coverage": round(min(1.0, total_weight / 2.0), 3),
    }


def weak_label(events: Iterable[dict[str, Any]]) -> dict[str, Any] | None:
    """
    A training target derived from rule agreement.

    Returned only when at least one pattern matched with real confidence,
    because a label of "nothing matched" carries no information about intent and
    training on it would teach the model to predict the prior.
    """
    result = score(events)
    if not result["match_ids"] or result["coverage"] < 0.25:
        return None
    return {
        "intent": result["intent"],
        "intel_gain": result["intel_gain"],
        "suspicion": result["suspicion"],
        "source_patterns": result["match_ids"],
        "coverage": result["coverage"],
    }
