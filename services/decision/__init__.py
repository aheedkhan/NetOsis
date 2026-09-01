"""Decision plane — P0/P1/P2 policies with optional GNN scorer integration."""

from __future__ import annotations

import asyncio
import json
import os
import urllib.error
import urllib.request
from collections import deque
from ipaddress import ip_address, ip_network
from pathlib import Path

from cs.actors import ActorMap
from cs.activity import pick_global_level, summarize_actor
from cs.belief import belief_from_actor_rec, default_intent, sync_belief_to_rec
from cs.operator import classify
from cs.policies import PolicyEngine, _apply_level, MANIFEST_BY_LEVEL
from cs.patterns import score as pattern_score
from cs.scoring import apply_gnn_scores, apply_pattern_scores
from cs.transitions import transition_event
from cs.tinyhttp import json_body, serve

BIND = os.environ.get("CS_BIND", "0.0.0.0")
PORT = int(os.environ.get("CS_PORT", "9000"))
POLICY = os.environ.get("CS_POLICY", "P0")
CONFIG_DIR = Path(os.environ.get("CS_CONFIG_DIR", "/config"))
CURRENT = Path(os.environ.get("CS_MANIFEST_CURRENT", "/data/manifests/current.json"))
PIN = CURRENT.parent / ".pinned"
LOGGER_HOST = os.environ.get("CS_LOGGER_HOST", "10.200.1.11")
LOGGER_PORT = int(os.environ.get("CS_LOGGER_PORT", "8088"))
GNN_HOST = os.environ.get("CS_GNN_HOST", "")
GNN_PORT = int(os.environ.get("CS_GNN_PORT", "9100"))
GNN_ENABLED = os.environ.get("CS_GNN_ENABLED", "0") == "1"

# Operator classification. The gate is part of the adaptive treatment, so it is
# off for the static control arm unless explicitly forced on.
OPERATOR_GATE = os.environ.get("CS_OPERATOR_GATE", "1") == "1"
OPERATOR_WINDOW = int(os.environ.get("CS_OPERATOR_WINDOW", "200"))

# fw_agent endpoints, "host:port" comma separated. Blocking is best-effort and
# never on the request path: a firewall that cannot be reached must not stop
# the decision plane from deciding.
FIREWALLS = [
    hp.strip()
    for hp in os.environ.get(
        "CS_FIREWALLS", "10.200.1.30:9400,10.200.1.31:9400"
    ).split(",")
    if hp.strip()
]
BLOCK_TTL_S = int(os.environ.get("CS_BLOCK_TTL_S", "21600"))

# Blocking is a coercive action, so it is allowlisted rather than denylisted.
# Only addresses inside a range we have declared hostile may ever be dropped,
# and the infrastructure ranges are refused a second time on the way out. The
# failure this prevents is real: the control plane polls itself on a timer, and
# a timer is the most machine-like signal there is, so an unguarded classifier
# will happily conclude that the management network is a scanner and firewall
# the system away from its own sensors.
BLOCKABLE_CIDRS = [
    ip_network(c.strip())
    for c in os.environ.get("CS_BLOCKABLE_CIDRS", "203.0.113.0/24").split(",")
    if c.strip()
]
NEVER_BLOCK_CIDRS = [
    ip_network(c)
    for c in (
        "127.0.0.0/8", "10.200.1.0/24", "10.200.2.0/24", "10.200.3.0/24",
        "10.10.20.0/24", "10.10.30.0/24", "172.31.10.0/24", "172.31.99.0/24",
    )
]


def blockable(address: str) -> tuple[bool, str]:
    """Whether this source address is eligible to be dropped at the boundary."""
    try:
        ip = ip_address(address)
    except ValueError:
        return False, "not a valid address"
    for net in NEVER_BLOCK_CIDRS:
        if ip in net:
            return False, f"protected infrastructure range {net}"
    if BLOCKABLE_CIDRS and not any(ip in net for net in BLOCKABLE_CIDRS):
        return False, "outside the declared hostile range"
    return True, ""

actors = ActorMap()
belief_store: dict[str, dict] = {}
actor_levels: dict[str, str] = {}
transitions: list[dict] = []
engine = PolicyEngine(CONFIG_DIR, policy=POLICY)
last_event: dict | None = None
seen = 0
_gnn_cache: dict[str, dict] = {}

# Rolling per-actor event window. The operator classifier reasons over a
# sequence — timing regularity, think time, a typo followed by its correction —
# so a single event carries almost none of the signal.
actor_events: dict[str, deque] = {}
blocked_actors: dict[str, dict] = {}
_block_refusals: dict[str, str] = {}


def persist(manifest: dict) -> None:
    CURRENT.parent.mkdir(parents=True, exist_ok=True)
    tmp = CURRENT.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    tmp.replace(CURRENT)


def _fetch_gnn(actor_key: str) -> dict | None:
    if not GNN_ENABLED or not GNN_HOST:
        return _gnn_cache.get(actor_key)
    if actor_key in _gnn_cache:
        return _gnn_cache[actor_key]
    url = f"http://{GNN_HOST}:{GNN_PORT}/v1/score/{actor_key}"
    try:
        raw = urllib.request.urlopen(url, timeout=0.15).read()
        data = json.loads(raw)
        _gnn_cache[actor_key] = data
        return data
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
        return _gnn_cache.get(actor_key)


def _emit_to_logger(event: dict) -> None:
    try:
        data = json.dumps(event).encode()
        req = urllib.request.Request(
            f"http://{LOGGER_HOST}:{LOGGER_PORT}/v1/events",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=0.25)
    except (urllib.error.URLError, TimeoutError, OSError):
        pass


def _post_firewall(path: str, payload: dict) -> list[str]:
    """Best-effort fan-out to every firewall agent. Returns the ones that took it."""
    accepted: list[str] = []
    data = json.dumps(payload).encode()
    for endpoint in FIREWALLS:
        try:
            req = urllib.request.Request(
                f"http://{endpoint}{path}",
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=0.4) as resp:
                if 200 <= resp.status < 300:
                    accepted.append(endpoint)
        except (urllib.error.URLError, TimeoutError, OSError):
            continue
    return accepted


def _actuate_block(belief, manifest: dict, dataset: str) -> None:
    """
    Push an automated actor onto the perimeter blocklist.

    Only source addresses that were actually observed are blocked, and each is
    blocked once. The resulting decision event is the audit record for a
    coercive action, so it carries the classifier's own reasoning rather than
    just the verdict.
    """
    addresses = list(belief.linked_ips or [])
    key = belief.actor_key
    if key.startswith("ip:"):
        addresses.append(key[3:])
    addresses = [a for a in dict.fromkeys(addresses) if a]
    if not addresses:
        return

    fresh = []
    for address in addresses:
        if address in blocked_actors:
            continue
        allowed, why = blockable(address)
        if not allowed:
            if address not in _block_refusals:
                _block_refusals[address] = why
                print(f"BLOCK REFUSED {address} actor={key}: {why}", flush=True)
            continue
        fresh.append(address)
    if not fresh:
        return

    for address in fresh:
        accepted = _post_firewall(
            "/v1/block", {"ip": address, "ttl_s": BLOCK_TTL_S}
        )
        blocked_actors[address] = {
            "actor_key": key,
            "firewalls": accepted,
            "ttl_s": BLOCK_TTL_S,
        }
        print(
            f"BLOCK {address} actor={key} p_human={belief.p_human:.3f} "
            f"firewalls={accepted or 'none reachable'}",
            flush=True,
        )
        tr = transition_event(
            actor_key=key,
            from_level=actor_levels.get(key, "L1"),
            to_level="BLOCK",
            policy=POLICY,
            rationale=(manifest.get("gate") or {}).get("reason")
            or "automated actor blocked at the perimeter",
            belief=belief.to_dict(),
            trigger_dataset=dataset,
        )
        tr.setdefault("cybersnare", {})["blocked_ip"] = address
        tr["cybersnare"]["firewalls_actuated"] = accepted
        tr["cybersnare"]["operator"] = manifest.get("operator")
        _emit_to_logger(tr)


def _build_global_manifest(per_actor: dict[str, dict]) -> dict:
    """Merge per-actor manifests — global posture = highest engagement level."""
    if not per_actor:
        seed = CONFIG_DIR / "manifest-l1.json"
        if seed.exists():
            return json.loads(seed.read_text(encoding="utf-8"))
        return {}
    levels = [m.get("level", "L1") for m in per_actor.values()]
    global_level = pick_global_level(levels)
    # The lead actor is the one the posture is actually for, so blocked actors
    # are not eligible: their manifest is a withdrawal, not an engagement.
    served = {
        k: m for k, m in per_actor.items() if m.get("level") not in ("BLOCK",)
    } or per_actor
    lead = max(served.values(), key=lambda m: m.get("belief", {}).get("behavioural_score", 0))
    base = engine._base(global_level if global_level in MANIFEST_BY_LEVEL else "L1")
    merged = _apply_level(base, global_level)
    merged["policy"] = POLICY
    merged["arm"] = {"P0": "A", "P1": "B", "P2": "C"}.get(POLICY, "A")
    merged["level"] = global_level
    blocked = sum(1 for m in per_actor.values() if m.get("level") == "BLOCK")
    merged["rationale"] = (
        f"Global manifest merged from {len(per_actor)} actor(s) → {global_level} "
        f"(lead actor {lead.get('actor_key', '?')}"
        + (f"; {blocked} blocked at the perimeter and excluded" if blocked else "")
        + ")"
    )
    merged["blocked_actors"] = blocked
    merged["actor_key"] = lead.get("actor_key")
    merged["belief"] = lead.get("belief")
    if lead.get("operator"):
        merged["operator"] = lead["operator"]
    if lead.get("gate"):
        merged["gate"] = lead["gate"]
    merged["linked_ips"] = lead.get("linked_ips")
    merged["linkage_confidence"] = lead.get("linkage_confidence")
    return merged


def apply_event(event: dict) -> dict:
    global last_event, seen
    dataset = (event.get("event") or {}).get("dataset") or ""
    if dataset.startswith("cybersnare.decision."):
        return json.loads(CURRENT.read_text(encoding="utf-8")) if CURRENT.exists() else {}

    seen += 1
    last_event = event
    rec = actors.resolve(event)
    rec["events"] = int(rec.get("events") or 0) + 1
    rec["last_dataset"] = dataset
    rec["last_seen"] = event.get("@timestamp")

    belief = belief_from_actor_rec(rec)
    gnn = _fetch_gnn(belief.actor_key)
    if gnn:
        apply_gnn_scores(belief, gnn)

    # Operator classification over this actor's recent history.
    window = actor_events.setdefault(belief.actor_key, deque(maxlen=OPERATOR_WINDOW))
    window.append(event)

    # Attack-pattern matching over the same window. Patterns are the only
    # evidence source that considers the ORDER of events, so they carry
    # information neither the per-event hints nor the graph model can recover.
    patterns = pattern_score(window)
    apply_pattern_scores(belief, patterns)

    assessment = classify(window) if OPERATOR_GATE else None
    if assessment is not None:
        belief.capability = assessment.capability
        belief.p_human = assessment.p_human
        belief.operator_confidence = assessment.confidence
        belief.operator_signals = [sig.to_dict() for sig in assessment.signals]

    prior_level = actor_levels.get(belief.actor_key, belief.posture or "L1")
    manifest = engine.evaluate(belief, event, rec, assessment=assessment)
    new_level = manifest.get("level", "L1")
    actor_levels[belief.actor_key] = new_level

    if new_level != prior_level and POLICY in ("P1", "P2") and not PIN.exists():
        rationale = manifest.get("rationale") or f"policy {POLICY} escalation"
        tr = transition_event(
            actor_key=belief.actor_key,
            from_level=prior_level,
            to_level=new_level,
            policy=POLICY,
            rationale=rationale,
            belief=belief.to_dict(),
            trigger_dataset=dataset,
        )
        transitions.append(
            {
                "@timestamp": tr.get("@timestamp"),
                "actor_key": belief.actor_key,
                "from_level": prior_level,
                "to_level": new_level,
                "rationale": rationale,
            }
        )
        if len(transitions) > 100:
            transitions.pop(0)
        _emit_to_logger(tr)

    if new_level == "BLOCK" and (manifest.get("actuation") or {}).get("firewall_block"):
        _actuate_block(belief, manifest, dataset)

    manifest["patterns"] = patterns["matches"]
    stored = belief.to_dict()
    stored["patterns"] = patterns["matches"]
    stored["pattern_ids"] = patterns["match_ids"]
    stored["pattern_coverage"] = patterns["coverage"]
    sync_belief_to_rec(belief, rec)

    for stale in [k for k in belief_store if k not in actors.actors]:
        belief_store.pop(stale, None)
        actor_levels.pop(stale, None)
        actor_events.pop(stale, None)

    event.setdefault("session", {})["actor_key"] = belief.actor_key
    event.setdefault("session", {})["level"] = belief.level
    event.setdefault("cybersnare", {})["linkage_confidence"] = rec.get(
        "linkage_confidence"
    )

    if PIN.exists() and CURRENT.exists():
        try:
            pinned = json.loads(CURRENT.read_text(encoding="utf-8"))
            for key in (
                "belief",
                "generated_at",
                "actor_key",
                "events_seen",
                "linked_ips",
                "linkage_confidence",
            ):
                if key in manifest:
                    pinned[key] = manifest[key]
            manifest = pinned
        except (json.JSONDecodeError, OSError):
            pass
    elif POLICY in ("P1", "P2"):
        per_actor = {}
        for key, b in belief_store.items():
            lvl = actor_levels.get(key, "L1")
            m = _apply_level(engine._base(lvl if lvl in MANIFEST_BY_LEVEL else "L1"), lvl)
            m["actor_key"] = key
            m["belief"] = b
            if b.get("operator_signals") is not None:
                m["operator"] = {
                    "capability": b.get("capability"),
                    "p_human": b.get("p_human"),
                    "confidence": b.get("operator_confidence"),
                    "signals": b.get("operator_signals") or [],
                }
            m["linked_ips"] = b.get("linked_ips", [])
            m["linkage_confidence"] = actors.actors.get(key, {}).get(
                "linkage_confidence", "none"
            )
            per_actor[key] = m
        manifest = _build_global_manifest(per_actor)

    manifest["events_seen"] = seen
    manifest["active_actors"] = len(belief_store)
    persist(manifest)
    return manifest


async def handler(req: dict) -> tuple[int, dict[str, str], bytes]:
    path, method = req["path"], req["method"]
    if method == "GET" and path == "/health":
        body = json.dumps(
            {
                "ok": True,
                "policy": POLICY,
                "gnn_enabled": GNN_ENABLED,
                "actors": len(belief_store),
                "events_seen": seen,
            }
        ).encode()
        return 200, {"Content-Type": "application/json"}, body
    if method == "GET" and path == "/v1/manifest":
        if CURRENT.exists():
            return 200, {"Content-Type": "application/json"}, CURRENT.read_bytes()
        seed = CONFIG_DIR / "manifest-l1.json"
        if seed.exists():
            return 200, {"Content-Type": "application/json"}, seed.read_bytes()
        return 404, {"Content-Type": "text/plain"}, b"no manifest\n"
    if method == "GET" and path == "/v1/belief":
        return 200, {"Content-Type": "application/json"}, json.dumps(
            {"actors": belief_store}
        ).encode()
    if method == "GET" and path == "/v1/activity":
        manifest = {}
        if CURRENT.exists():
            try:
                manifest = json.loads(CURRENT.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                manifest = {}
        actor_rows = [summarize_actor(k, v) for k, v in belief_store.items()]
        body = json.dumps(
            {
                "policy": POLICY,
                "gnn_enabled": GNN_ENABLED,
                "manifest": manifest,
                "actors": actor_rows,
                "transitions": transitions[-20:],
                "events_seen": seen,
            }
        ).encode()
        return 200, {"Content-Type": "application/json"}, body
    if method == "POST" and path == "/v1/manifest/pin":
        try:
            body = json_body(req) or {}
        except Exception:
            return 400, {"Content-Type": "text/plain"}, b"invalid json\n"
        if not isinstance(body, dict):
            return 400, {"Content-Type": "text/plain"}, b"invalid manifest\n"
        persist(body)
        PIN.touch()
        return 204, {}, b""
    if method == "DELETE" and path == "/v1/manifest/pin":
        if PIN.exists():
            PIN.unlink()
        return 204, {}, b""
    if method == "POST" and path.startswith("/v1/intent/"):
        actor_key = path.removeprefix("/v1/intent/").strip("/")
        if not actor_key:
            return 400, {"Content-Type": "text/plain"}, b"missing actor\n"
        try:
            body = json_body(req) or {}
        except Exception:
            return 400, {"Content-Type": "text/plain"}, b"invalid json\n"
        rec = actors.actors.get(actor_key)
        if rec:
            belief = belief_from_actor_rec(rec)
            if isinstance(body.get("intent"), dict):
                belief.intent = {k: float(v) for k, v in body["intent"].items()}
            elif body.get("objective") in belief.intent:
                belief.intent = default_intent()
                belief.intent[str(body["objective"])] = float(body.get("confidence") or 0.8)
                total = sum(belief.intent.values()) or 1.0
                belief.intent = {k: v / total for k, v in belief.intent.items()}
            belief_store[actor_key] = belief.to_dict()
            sync_belief_to_rec(belief, rec)
        return 204, {}, b""
    if method == "POST" and path == "/v1/event":
        try:
            event = json_body(req)
        except Exception:
            return 400, {"Content-Type": "text/plain"}, b"invalid json\n"
        if not isinstance(event, dict):
            return 400, {"Content-Type": "text/plain"}, b"invalid event\n"
        apply_event(event)
        return 204, {}, b""
    return 404, {"Content-Type": "text/plain"}, b"not found\n"


async def main() -> None:
    seed = CONFIG_DIR / "manifest-l1.json"
    if seed.exists():
        persist(json.loads(seed.read_text(encoding="utf-8")))
    server = await serve(BIND, PORT, handler, name="decision")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
