"""
Operator classification — is this a tool, or is it a person?

The deception ladder is expensive. A restricted shell, a populated filesystem
and an internal hop cost real memory, real disk and real analyst attention, and
the overwhelming majority of what arrives at an Internet-facing surface is a
scanner that will never read any of it. Spending L2 on a mass scanner buys
nothing: it produces a session transcript of a script executing a fixed list.

So capability is treated as a gate rather than as a score:

    automated             -> drop at the firewall. Nothing further to learn.
    scripted              -> observe at L1. Cheap, still recorded.
    interactive_operator  -> escalate. This is the traffic the study is about.

Every signal below is evidence about one question — was there a person in the
loop — and each is combined as a log-odds contribution rather than a threshold,
so no single observation can decide the outcome on its own. That matters
because the expensive error is asymmetric: dropping a human is a lost
observation that cannot be recovered, while engaging a bot merely wastes a
container. The thresholds are deliberately set to prefer the second mistake.
"""

from __future__ import annotations

import math
import re
import statistics
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Iterable

# --------------------------------------------------------------------------
# Tool fingerprints
# --------------------------------------------------------------------------

# Substrings that appear in the user-agent of a scanner or exploitation tool.
# Presence is strong machine evidence; absence proves nothing, because a
# careful operator sets a browser user-agent.
TOOL_AGENTS: tuple[str, ...] = (
    "nmap", "masscan", "zgrab", "zmap", "nikto", "sqlmap", "dirb", "gobuster",
    "ffuf", "wpscan", "hydra", "medusa", "nuclei", "httpx", "whatweb",
    "acunetix", "nessus", "openvas", "qualys", "censys", "shodan",
    "python-requests", "python-urllib", "go-http-client", "libwww-perl",
    "okhttp", "apache-httpclient", "curl/", "wget/", "scrapy", "aiohttp",
)

# Automation libraries speaking SSH. OpenSSH is deliberately absent: it is what
# a human at a terminal uses, so treating it as machine evidence would invert
# the signal.
TOOL_SSH_CLIENTS: tuple[str, ...] = (
    "paramiko", "libssh", "go", "russh", "jsch", "sshj", "phpseclib",
    "renci", "nmap", "hydra", "medusa", "crowbar",
)

# Browsers. Weak human evidence only — trivially forged, and a scanner that
# sets one is exactly the sort that also behaves like a scanner in every other
# respect, which the timing signals will catch.
BROWSER_AGENTS: tuple[str, ...] = (
    "mozilla/", "chrome/", "safari/", "firefox/", "edg/", "opera",
)

# Commands that a human types while orienting and a script almost never does,
# because a script already knows what it came for.
ORIENTING_COMMANDS: tuple[str, ...] = (
    "whoami", "pwd", "id", "ls", "ll", "cd", "cat", "less", "more", "history",
    "uname", "hostname", "df", "free", "ps", "top", "w", "who", "env", "which",
)

_WS = re.compile(r"\s+")


# --------------------------------------------------------------------------
# Result types
# --------------------------------------------------------------------------

@dataclass
class OperatorSignal:
    """One piece of evidence, with the direction and strength of its vote."""

    name: str
    verdict: str  # "human" | "machine" | "neutral"
    weight: float  # log-odds contribution, signed at combination time
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "verdict": self.verdict,
            "weight": round(self.weight, 3),
            "detail": self.detail,
        }


@dataclass
class OperatorAssessment:
    capability: str  # automated | scripted | interactive_operator
    p_human: float
    confidence: float
    signals: list[OperatorSignal] = field(default_factory=list)
    observations: int = 0

    @property
    def should_block(self) -> bool:
        """Automated and confidently so — drop it at the boundary."""
        return self.capability == "automated" and self.confidence >= BLOCK_CONFIDENCE

    @property
    def should_engage(self) -> bool:
        """A person appears to be present — this is what deception is for."""
        return self.capability == "interactive_operator"

    def to_dict(self) -> dict[str, Any]:
        return {
            "capability": self.capability,
            "p_human": round(self.p_human, 4),
            "confidence": round(self.confidence, 4),
            "observations": self.observations,
            "should_block": self.should_block,
            "should_engage": self.should_engage,
            "signals": [s.to_dict() for s in self.signals],
        }


# --------------------------------------------------------------------------
# Tuning
# --------------------------------------------------------------------------

# Enough evidence to spend a firewall drop on. Set high on purpose: a dropped
# human is an observation that can never be recovered, whereas an engaged bot
# costs one container for a few minutes.
BLOCK_CONFIDENCE = 0.80

# Below this many events nothing is decided, because the timing signals need a
# sequence before they mean anything.
MIN_OBSERVATIONS = 4

HUMAN_THRESHOLD = 0.62
MACHINE_THRESHOLD = 0.32


# --------------------------------------------------------------------------
# Helpers
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


def _dataset(event: dict[str, Any]) -> str:
    return (event.get("event") or {}).get("dataset") or ""


def _levenshtein(a: str, b: str, cap: int = 3) -> int:
    """Bounded edit distance. Only small distances matter here."""
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(
                min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ca != cb))
            )
        previous = current
        if min(previous) > cap:
            return cap + 1
    return previous[-1]


# --------------------------------------------------------------------------
# Individual signals
# --------------------------------------------------------------------------

def _signal_tool_agent(events: list[dict[str, Any]]) -> OperatorSignal | None:
    agents = {
        (e.get("network") or {}).get("ua_signature", "").lower()
        for e in events
        if (e.get("network") or {}).get("ua_signature")
    }
    for agent in agents:
        for tool in TOOL_AGENTS:
            if tool in agent:
                return OperatorSignal(
                    "tool_user_agent", "machine", 2.2,
                    f"user-agent identifies {tool!r}",
                )
    for agent in agents:
        if any(b in agent for b in BROWSER_AGENTS):
            return OperatorSignal(
                "browser_user_agent", "human", 0.5,
                "user-agent claims a browser (weak — trivially forged)",
            )
    return None


def _signal_ssh_client(events: list[dict[str, Any]]) -> OperatorSignal | None:
    versions = {
        str((e.get("ssh") or {}).get("client_version", "")).lower()
        for e in events
        if (e.get("ssh") or {}).get("client_version")
    }
    for version in versions:
        for tool in TOOL_SSH_CLIENTS:
            if tool in version:
                return OperatorSignal(
                    "automation_ssh_client", "machine", 2.0,
                    f"SSH client string contains {tool!r}",
                )
    return None


def _signal_timing_regularity(events: list[dict[str, Any]]) -> OperatorSignal | None:
    """
    A loop emits events on a metronome. A person does not.

    The coefficient of variation of the inter-arrival gaps separates the two
    more reliably than the raw rate does, because a slow script is still a
    regular one while a fast typist is still an irregular one.
    """
    stamps = sorted(t for t in (_ts(e) for e in events) if t is not None)
    if len(stamps) < 5:
        return None
    gaps = [b - a for a, b in zip(stamps, stamps[1:]) if b - a >= 0]
    gaps = [g for g in gaps if g < 600]  # ignore idle periods between sessions
    if len(gaps) < 4:
        return None
    mean = statistics.fmean(gaps)
    if mean <= 0:
        return None
    cv = statistics.pstdev(gaps) / mean
    median = statistics.median(gaps)

    if cv < 0.35:
        return OperatorSignal(
            "metronomic_timing", "machine", 1.8,
            f"inter-event coefficient of variation {cv:.2f} over {len(gaps)} gaps",
        )
    # Irregularity only means a person if the events are spaced like a person
    # in the first place. A fast sweep with one slow request afterwards has a
    # high coefficient of variation and no human anywhere near it, so the
    # median gap has to be in human range before this votes.
    if cv > 0.85 and median >= 0.3:
        return OperatorSignal(
            "irregular_timing", "human", 1.1,
            f"coefficient of variation {cv:.2f}, median gap {median:.1f}s",
        )
    return None


def _signal_machine_speed(events: list[dict[str, Any]]) -> OperatorSignal | None:
    """Sustained sub-100ms spacing is below human reaction time."""
    stamps = sorted(t for t in (_ts(e) for e in events) if t is not None)
    if len(stamps) < 6:
        return None
    gaps = [b - a for a, b in zip(stamps, stamps[1:])]
    fast = sum(1 for g in gaps if 0 <= g < 0.1)
    if fast >= max(4, int(0.7 * len(gaps))):
        return OperatorSignal(
            "superhuman_rate", "machine", 2.0,
            f"{fast}/{len(gaps)} gaps under 100ms",
        )
    return None


def _signal_scan_breadth(events: list[dict[str, Any]]) -> OperatorSignal | None:
    """Many distinct ports in a short window is a sweep, not curiosity."""
    ports: set[int] = set()
    stamps: list[float] = []
    for e in events:
        if not _dataset(e).startswith("cybersnare.fw."):
            continue
        port = (e.get("destination") or {}).get("port")
        if isinstance(port, int):
            ports.add(port)
        t = _ts(e)
        if t is not None:
            stamps.append(t)
    if len(ports) < 8 or not stamps:
        return None
    span = max(stamps) - min(stamps)
    if span <= 60:
        return OperatorSignal(
            "port_sweep", "machine", 2.1,
            f"{len(ports)} distinct ports in {span:.0f}s",
        )
    return None


def _signal_think_time(events: list[dict[str, Any]]) -> OperatorSignal | None:
    """
    The pause between getting a shell and typing the first command.

    A person reads the prompt. A script has its first command already queued.
    """
    auth_at: float | None = None
    for e in sorted(events, key=lambda x: _ts(x) or 0):
        ds = _dataset(e)
        t = _ts(e)
        if t is None:
            continue
        if ds == "cybersnare.ssh.auth" and (e.get("event") or {}).get("action") in (
            "auth_success", "shell_open"
        ):
            auth_at = t
        elif ds == "cybersnare.shell.command" and auth_at is not None:
            delta = t - auth_at
            if delta < 0.35:
                return OperatorSignal(
                    "no_think_time", "machine", 1.6,
                    f"first command {delta * 1000:.0f}ms after authentication",
                )
            if delta > 1.5:
                return OperatorSignal(
                    "think_time", "human", 1.3,
                    f"first command {delta:.1f}s after authentication",
                )
            return None
    return None


def _signal_typo_correction(events: list[dict[str, Any]]) -> OperatorSignal | None:
    """
    The strongest single human signal available.

    A mistyped command followed shortly by a near-identical corrected one is
    something a script has no reason to produce. Edit distance is bounded at
    two so that genuinely different commands do not register.
    """
    commands: list[tuple[float, str]] = []
    for e in events:
        if _dataset(e) != "cybersnare.shell.command":
            continue
        cmd = (e.get("process") or {}).get("command_line") or (
            e.get("cybersnare") or {}
        ).get("command")
        t = _ts(e)
        if isinstance(cmd, str) and cmd.strip() and t is not None:
            commands.append((t, _WS.sub(" ", cmd.strip())))
    commands.sort()

    for (t1, c1), (t2, c2) in zip(commands, commands[1:]):
        if c1 == c2 or t2 - t1 > 25:
            continue
        distance = _levenshtein(c1, c2)
        if 1 <= distance <= 2 and min(len(c1), len(c2)) >= 3:
            return OperatorSignal(
                "typo_correction", "human", 2.4,
                f"{c1!r} corrected to {c2!r} after {t2 - t1:.1f}s",
            )
    return None


def _signal_orienting(events: list[dict[str, Any]]) -> OperatorSignal | None:
    """A person looks around first; a script goes straight to its objective."""
    commands = [
        str((e.get("process") or {}).get("command_line") or "").strip().split()[:1]
        for e in events
        if _dataset(e) == "cybersnare.shell.command"
    ]
    heads = [c[0].lower() for c in commands if c]
    if len(heads) < 3:
        return None
    orienting = sum(1 for h in heads if h in ORIENTING_COMMANDS)
    ratio = orienting / len(heads)
    if ratio >= 0.5:
        return OperatorSignal(
            "orienting_behaviour", "human", 1.2,
            f"{orienting}/{len(heads)} commands are orientation",
        )
    return None


def _signal_repetition(events: list[dict[str, Any]]) -> OperatorSignal | None:
    """A fixed command list repeated verbatim is a playbook, not a person."""
    commands = [
        _WS.sub(" ", str((e.get("process") or {}).get("command_line") or "").strip())
        for e in events
        if _dataset(e) == "cybersnare.shell.command"
    ]
    commands = [c for c in commands if c]
    if len(commands) < 6:
        return None
    unique = len(set(commands))
    if unique / len(commands) < 0.4:
        return OperatorSignal(
            "replayed_command_list", "machine", 1.5,
            f"only {unique} unique of {len(commands)} commands",
        )
    return None


def _signal_auth_burst(events: list[dict[str, Any]]) -> OperatorSignal | None:
    """
    Repeated authentication failure is the most common automated behaviour on
    the Internet and never reaches a shell, so none of the command-level
    signals can see it. A person trying a remembered password gives up after a
    handful of attempts; a sprayer does not.
    """
    stamps = sorted(
        t
        for t in (
            _ts(e)
            for e in events
            if _dataset(e) in ("cybersnare.ssh.auth", "cybersnare.http.request")
            and (e.get("event") or {}).get("action")
            in ("auth_fail", "auth_failure", "login_failed")
        )
        if t is not None
    )
    if len(stamps) < 6:
        return None
    span = stamps[-1] - stamps[0]
    rate = len(stamps) / max(span, 1e-6)
    if span <= 120 or rate > 0.2:
        return OperatorSignal(
            "credential_spray", "machine", 1.9,
            f"{len(stamps)} failed authentications in {span:.0f}s",
        )
    return None


def _signal_session_depth(events: list[dict[str, Any]]) -> OperatorSignal | None:
    """
    Breadth of interaction. Scanners touch one thing and leave; operators move
    between surfaces as they build a picture.
    """
    datasets = {_dataset(e) for e in events if _dataset(e)}
    interactive = {
        "cybersnare.shell.command",
        "cybersnare.ssh.auth",
        "cybersnare.http.request",
    }
    touched = datasets & interactive
    if len(datasets) >= 5 and len(touched) >= 2:
        return OperatorSignal(
            "multi_surface_engagement", "human", 1.0,
            f"{len(datasets)} datasets across {len(touched)} interactive surfaces",
        )
    if datasets and datasets <= {"cybersnare.fw.drop", "cybersnare.fw.icmp",
                                "cybersnare.zeek.conn"}:
        return OperatorSignal(
            "probe_only", "machine", 1.4,
            "connection probes only, no protocol interaction",
        )
    return None


SIGNALS = (
    _signal_tool_agent,
    _signal_ssh_client,
    _signal_timing_regularity,
    _signal_machine_speed,
    _signal_scan_breadth,
    _signal_think_time,
    _signal_typo_correction,
    _signal_orienting,
    _signal_auth_burst,
    _signal_repetition,
    _signal_session_depth,
)


# --------------------------------------------------------------------------
# Combination
# --------------------------------------------------------------------------

def classify(events: Iterable[dict[str, Any]]) -> OperatorAssessment:
    """
    Combine every available signal into a single assessment.

    Contributions are summed in log-odds and squashed once, so two weak
    agreeing signals cannot outvote one strong disagreeing one by accident, and
    no single signal saturates the result.
    """
    evs = [e for e in events if isinstance(e, dict)]
    signals: list[OperatorSignal] = []
    for detector in SIGNALS:
        try:
            found = detector(evs)
        except Exception:
            found = None  # a broken signal must not break classification
        if found is not None:
            signals.append(found)

    log_odds = 0.0
    for signal in signals:
        if signal.verdict == "human":
            log_odds += signal.weight
        elif signal.verdict == "machine":
            log_odds -= signal.weight

    p_human = 1.0 / (1.0 + math.exp(-log_odds))

    if len(evs) < MIN_OBSERVATIONS:
        # Not enough to judge. Treat as scripted: cheap to serve, still logged,
        # and revisited on the next event.
        return OperatorAssessment(
            capability="scripted",
            p_human=p_human,
            confidence=0.0,
            signals=signals,
            observations=len(evs),
        )

    if p_human >= HUMAN_THRESHOLD:
        capability = "interactive_operator"
    elif p_human <= MACHINE_THRESHOLD:
        capability = "automated"
    else:
        capability = "scripted"

    return OperatorAssessment(
        capability=capability,
        p_human=p_human,
        confidence=abs(p_human - 0.5) * 2.0,
        signals=signals,
        observations=len(evs),
    )
