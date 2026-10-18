"""Behavioural persona for an attacker, derived only from what they did.

One function, used in two places so they can never disagree:
  * ActorProfile.to_rag_text()  -> the LLM sees "Behaviour so far: ..." for the
    CURRENT attacker, so unseen commands are answered in character for them.
  * the SOC dashboard           -> the label, tags and avatar on each profile card.

Rules are intentionally plain and explainable (viva-friendly): each tag lists
the exact evidence that triggered it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable

# Most-serious first: the first matching tag becomes the primary persona.
_TAGS: list[tuple[str, str, str]] = [
    ("lateral_mover", "Lateral mover", "is moving between hosts over SSH"),
    ("dropper", "Dropper", "is pulling tools or payloads onto the host"),
    ("persistence", "Entrenching", "is trying to keep access (cron, keys, services)"),
    ("cleaner", "Covering tracks", "is deleting logs or history"),
    ("credential_hunter", "Credential hunter", "is looking for passwords and keys"),
    ("explorer", "Explorer", "is browsing files and accounts by hand"),
    ("scanner", "Scanner", "is probing the host and network"),
]

_CRED = re.compile(
    r"etc/shadow|id_(rsa|ed25519|ecdsa)|\.pgpass|\.env\b|credential|passw|db\.url|"
    r"\.bash_history|^\s*history\b|authorized_keys|wp-config",
    re.I,
)
_DROP = re.compile(r"\b(wget|curl|tftp|ftp|git\s+clone|pip\s+install|chmod\s+(\+x|[0-7]*7))\b|^\./|^/tmp/", re.I)
_PERSIST = re.compile(r"crontab\s+(-e|[^\s-])|etc/cron|authorized_keys|systemctl\s+(enable|start)|\.bashrc|rc\.local", re.I)
_CLEAN = re.compile(r"/var/log|history\s+-c|unset\s+HISTFILE|shred\s|\.bash_history.*(>|rm)|rm\s.*\.bash_history", re.I)
_LATERAL = re.compile(r"^\s*(sudo\s+)?(ssh|scp|sftp)\s+\S", re.I)
_RECON = re.compile(r"^\s*(nmap|ping|nc|ncat|netcat|telnet|arp|dig|nslookup|host|traceroute|ss|netstat|ip|ifconfig|uname|id|whoami|hostname|uptime|w|who)\b", re.I)
_BROWSE = re.compile(r"^\s*(ls|cd|cat|find|grep|less|more|head|tail|stat|file|pwd)\b", re.I)


@dataclass
class Persona:
    id: str
    label: str
    summary: str
    tags: list[str] = field(default_factory=list)
    evidence: dict[str, list[str]] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "label": self.label,
            "summary": self.summary,
            "tags": list(self.tags),
            "evidence": {k: list(v) for k, v in self.evidence.items()},
        }


def classify(
    commands: Iterable[str],
    *,
    categories: Iterable[str] = (),
    packages: Iterable[str] = (),
    sandbox_jobs: int = 0,
    auth_failures: int = 0,
) -> Persona:
    cmds = [c for c in commands if c]
    cats = set(categories)
    hits: dict[str, list[str]] = {}

    def add(tag: str, cmd: str) -> None:
        bucket = hits.setdefault(tag, [])
        if cmd not in bucket and len(bucket) < 4:
            bucket.append(cmd)

    for c in cmds:
        if _LATERAL.search(c):
            add("lateral_mover", c)
        if _DROP.search(c):
            add("dropper", c)
        if _PERSIST.search(c):
            add("persistence", c)
        if _CLEAN.search(c):
            add("cleaner", c)
        if _CRED.search(c):
            add("credential_hunter", c)
        if _BROWSE.search(c):
            add("explorer", c)
        if _RECON.search(c):
            add("scanner", c)

    if "Lateral_movement" in cats:
        hits.setdefault("lateral_mover", ["(pivot to another honeypot)"])
    if sandbox_jobs or list(packages):
        hits.setdefault("dropper", ["(sandbox/package activity)"])
    if "Credential_attack" in cats and "credential_hunter" not in hits:
        hits["credential_hunter"] = ["(credential-related commands)"]

    # A scanner that also browses by hand is really an explorer; only call it a
    # scanner when probing is all (or nearly all) there is.
    if "scanner" in hits and "explorer" in hits and len(hits["explorer"]) >= 2:
        hits.pop("scanner")
    if "explorer" in hits and any(t in hits for t in ("credential_hunter", "lateral_mover", "dropper")):
        hits.pop("explorer", None)

    if not cmds and auth_failures:
        return Persona(
            "brute_forcer", "Brute-forcer", f"has tried {auth_failures} logins and never reached a shell",
            ["brute_forcer"], {"brute_forcer": [f"{auth_failures} failed logins"]},
        )
    if not hits:
        return Persona("opportunist", "Opportunist", "has only just arrived", [], {})

    ordered = [t for t in _TAGS if t[0] in hits]
    primary = ordered[0]
    return Persona(
        primary[0], primary[1], primary[2],
        [t[0] for t in ordered], {t[0]: hits[t[0]] for t in ordered},
    )
