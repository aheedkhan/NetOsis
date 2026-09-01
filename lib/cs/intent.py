"""Slow-path intent inference — out of band, never on the request path (§6.5)."""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from typing import Any

from cs.belief import OBJECTIVES, default_intent

# Grammar-constrained output shape for LLM slow path.
INTENT_SCHEMA = {
    "objective": "one of OBJECTIVES",
    "confidence": "0.0-1.0",
    "predicted_next_actions": ["list of strings"],
    "recommended_manifest": "L0|L1|L2|L3|BURN",
    "rationale": "short string",
}


def _rule_based(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Deterministic fallback when LLM is unavailable (design §2.3 graceful degradation)."""
    intent = default_intent()
    cmds: list[str] = []
    for ev in events:
        ds = (ev.get("event") or {}).get("dataset") or ""
        hints = {
            "cybersnare.ssh.auth": ("credential_spray", 0.35),
            "cybersnare.http.request": ("credential_spray", 0.3),
            "cybersnare.shell.command": ("exploit_attempt", 0.25),
            "cybersnare.sinkhole.dns": ("exfiltration", 0.3),
            "cybersnare.sinkhole.http": ("exfiltration", 0.35),
            "cybersnare.zeek.conn": ("recon_scan", 0.2),
        }
        if ds in hints:
            obj, w = hints[ds]
            intent[obj] = intent.get(obj, 0.0) + w
        shell = (ev.get("extra") or {}).get("shell") or {}
        if shell.get("command"):
            cmds.append(str(shell["command"]))
    total = sum(intent.values()) or 1.0
    for k in intent:
        intent[k] /= total
    top = max(intent, key=intent.get)
    mapping = {
        "recon_scan": "L1",
        "credential_spray": "L2",
        "exploit_attempt": "L2",
        "lateral_movement": "L3",
        "exfiltration": "L3",
        "unknown": "L1",
    }
    next_actions: list[str] = []
    if any("wget" in c or "curl" in c for c in cmds):
        next_actions.append("outbound_fetch")
    if any("sudo" in c for c in cmds):
        next_actions.append("privilege_escalation")
    if not next_actions:
        next_actions.append("continue_enumeration")
    return {
        "objective": top,
        "confidence": round(float(intent[top]), 4),
        "intent": {k: round(v, 4) for k, v in intent.items()},
        "predicted_next_actions": next_actions,
        "recommended_manifest": mapping.get(top, "L1"),
        "rationale": f"rule-based: dominant objective {top} from {len(events)} events",
        "source": "rules",
    }


def _llm_prompt(events: list[dict[str, Any]]) -> str:
    slim = []
    for ev in events[-40:]:
        slim.append(
            {
                "dataset": (ev.get("event") or {}).get("dataset"),
                "action": (ev.get("event") or {}).get("action"),
                "user": (ev.get("user") or {}).get("name"),
                "source": (ev.get("source") or {}).get("ip"),
                "shell": (ev.get("extra") or {}).get("shell"),
            }
        )
    return (
        "You are a cyber deception analyst. Given session events, emit JSON only with keys: "
        "objective (one of "
        + ", ".join(OBJECTIVES)
        + "), confidence (0-1), predicted_next_actions (array), "
        "recommended_manifest (L0|L1|L2|L3|BURN), rationale (string).\n\n"
        f"Events:\n{json.dumps(slim, indent=2)}"
    )


def _parse_llm_json(text: str) -> dict[str, Any] | None:
    match = re.search(r"\{[\s\S]*\}", text)
    if not match:
        return None
    try:
        data = json.loads(match.group(0))
    except json.JSONDecodeError:
        return None
    if data.get("objective") not in OBJECTIVES:
        return None
    return data


def _llm_infer(events: list[dict[str, Any]]) -> dict[str, Any] | None:
    api_key = os.environ.get("CS_LLM_API_KEY") or os.environ.get("OPENAI_API_KEY")
    if not api_key:
        return None
    base = os.environ.get("CS_LLM_BASE_URL", "https://api.openai.com/v1").rstrip("/")
    model = os.environ.get("CS_LLM_MODEL", "gpt-4o-mini")
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": "Respond with valid JSON only."},
            {"role": "user", "content": _llm_prompt(events)},
        ],
        "temperature": 0.1,
        "response_format": {"type": "json_object"},
    }
    req = urllib.request.Request(
        f"{base}/chat/completions",
        data=json.dumps(payload).encode(),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        raw = urllib.request.urlopen(req, timeout=30).read()
        body = json.loads(raw)
        content = body["choices"][0]["message"]["content"]
        parsed = _parse_llm_json(content)
        if not parsed:
            return None
        intent = default_intent()
        obj = parsed["objective"]
        intent[obj] = 0.85
        rest = (1.0 - 0.85) / (len(OBJECTIVES) - 1)
        for k in intent:
            if k != obj:
                intent[k] = rest
        parsed["intent"] = {k: round(v, 4) for k, v in intent.items()}
        parsed["source"] = "llm"
        return parsed
    except (urllib.error.URLError, TimeoutError, KeyError, json.JSONDecodeError, OSError):
        return None


def infer_intent_slow(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Slow-path intent inference for an actor session."""
    if not events:
        out = _rule_based([])
        out["rationale"] = "no events"
        return out
    if os.environ.get("CS_LLM_ENABLED", "0") == "1":
        llm = _llm_infer(events)
        if llm:
            return llm
    return _rule_based(events)
