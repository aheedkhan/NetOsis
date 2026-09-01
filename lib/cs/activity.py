"""Activity monitoring helpers — intelligence plane v0."""

from __future__ import annotations

from typing import Any

LEVEL_RANK = {"L0": 0, "L1": 1, "L2": 2, "L3": 3, "BURN": 4, "BLOCK": 5}


def level_rank(level: str) -> int:
    return LEVEL_RANK.get(level, 1)


def top_intent(intent: dict[str, float] | None) -> str:
    if not intent:
        return "unknown"
    return max(intent, key=lambda k: intent.get(k, 0))


def summarize_actor(key: str, belief: dict[str, Any]) -> dict[str, Any]:
    intent = belief.get("intent") or {}
    return {
        "actor_key": key,
        "level": belief.get("level") or belief.get("posture") or "L1",
        "events": belief.get("events", 0),
        "score": belief.get("behavioural_score", 0),
        "suspicion": belief.get("suspicion", 0),
        "novelty": belief.get("novelty", 0),
        "intent": top_intent(intent),
        "intent_dist": intent,
        "capability": belief.get("capability", "automated"),
        "linked_ips": belief.get("linked_ips", []),
        "last_dataset": belief.get("last_dataset"),
        "last_seen": belief.get("last_seen"),
    }


# BLOCK is a per-actor terminal, not a posture the surfaces can adopt. It is
# actuated at the firewall against one source address; the deception surfaces
# stay exactly as they were for everyone else. Including it in the global merge
# would mean a single scanner could take the whole deception offline, which is
# a denial of service against our own instrument.
GLOBAL_EXCLUDED_LEVELS = frozenset({"BLOCK"})


def pick_global_level(actor_levels: list[str]) -> str:
    """Highest engagement level any still-served actor warrants."""
    served = [lvl for lvl in actor_levels if lvl not in GLOBAL_EXCLUDED_LEVELS]
    if not served:
        return "L1"
    return max(served, key=level_rank)


def format_monitor(
    *,
    policy: str,
    manifest: dict[str, Any],
    actors: list[dict[str, Any]],
    transitions: list[dict[str, Any]],
    recent: list[dict[str, Any]],
) -> str:
    lines: list[str] = []
    lines.append("═" * 72)
    lines.append(" CyberSnare Activity Monitor — dynamic deception control plane")
    lines.append("═" * 72)
    lines.append(
        f" Policy {policy} │ global level {manifest.get('level', '?')} │ "
        f"manifest {manifest.get('manifest_id', '?')} │ arm {manifest.get('arm', '?')}"
    )
    caps = manifest.get("capabilities") or {}
    ssh_auth = (caps.get("ssh") or {}).get("auth", "closed")
    https_auth = (caps.get("https") or {}).get("auth", "closed")
    shell = (caps.get("shell") or {}).get("exposed", False)
    lines.append(
        f" Surfaces: SSH auth={ssh_auth} │ HTTPS auth={https_auth} │ shell={shell}"
    )
    lines.append("─" * 72)
    lines.append(" ACTORS (linked by HASSH/JA4 — not just IP)")
    lines.append(f" {'ACTOR':<28} {'LVL':<5} {'SCORE':<6} {'INTENT':<18} {'EVENTS':<6} LAST")
    lines.append("─" * 72)
    if not actors:
        lines.append(" (no actors yet — probe :2222 or :8443)")
    for a in sorted(actors, key=lambda x: -float(x.get("score") or 0))[:12]:
        last = (a.get("last_dataset") or "-").replace("cybersnare.", "")
        lines.append(
            f" {a['actor_key'][:27]:<28} {a.get('level','?'):<5} "
            f"{float(a.get('score',0)):<6.2f} {a.get('intent','?'):<18} "
            f"{a.get('events',0):<6} {last}"
        )
    lines.append("─" * 72)
    lines.append(" RECENT MANIFEST TRANSITIONS (dynamic deception)")
    if not transitions:
        lines.append(" (none yet — use ./cs up-adaptive for auto-escalation)")
    for t in transitions[-8:]:
        lines.append(
            f" {t.get('@timestamp','?')[11:19]}  "
            f"{t.get('actor_key','?'):<22} "
            f"{t.get('from_level','?')} → {t.get('to_level','?')}  "
            f"{t.get('rationale','')[:36]}"
        )
    lines.append("─" * 72)
    lines.append(" LIVE EVENTS")
    for ev in recent[-6:]:
        evd = ev.get("event") or {}
        src = (ev.get("source") or {}).get("ip") or "?"
        actor = (ev.get("session") or {}).get("actor_key") or "?"
        lines.append(
            f" {(ev.get('@timestamp') or '?')[11:19]}  "
            f"{str(evd.get('dataset','?')).replace('cybersnare.',''):<22} "
            f"{src:<15} {actor[:20]}"
        )
    lines.append("═" * 72)
    return "\n".join(lines)
