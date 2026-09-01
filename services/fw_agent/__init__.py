"""
Firewall telemetry agent.

nftables inside a container cannot log through NFLOG without a userspace log
daemon, and the kernel ring buffer belongs to the host rather than the network
namespace. Instead every interesting rule updates a dynamic set whose elements
carry per-element counters, keyed on the concatenation

    source address . destination address . destination port

This agent polls those sets, diffs the counters against the previous poll, and
emits one canonical event per source that moved. Perimeter and east-west
activity therefore enter the same append-only log as every other evidence
stream, with the adversary's true source address intact.
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
from typing import Any

from cs.events import new_event
from cs.ingest import emit
from cs.tinyhttp import serve

ROLE = os.environ.get("CS_FW_ROLE", "edge")
TABLE = os.environ.get("CS_FW_TABLE", "cs_edge")
POLL_S = float(os.environ.get("CS_FW_POLL", "3"))
BIND = os.environ.get("CS_BIND", "0.0.0.0")
PORT = int(os.environ.get("CS_FW_HEALTH_PORT", "9400"))

# set name -> (dataset, action, category, engage activity, capability)
SET_SPECS: dict[str, dict[str, Any]] = {
    "probe_accept": {
        "dataset": "cybersnare.fw.accept",
        "action": "perimeter_accept",
        "category": ["network"],
        "capability": "edge_firewall",
        "engage": "EAC0003",
    },
    "probe_drop": {
        "dataset": "cybersnare.fw.drop",
        "action": "perimeter_drop",
        "category": ["network", "intrusion_detection"],
        "capability": "edge_firewall",
        "engage": "EAC0003",
    },
    "probe_icmp": {
        "dataset": "cybersnare.fw.icmp",
        "action": "perimeter_icmp",
        "category": ["network"],
        "capability": "edge_firewall",
        "engage": "EAC0003",
        "no_port": True,
    },
    "lateral_accept": {
        "dataset": "cybersnare.fw.lateral",
        "action": "east_west_accept",
        "category": ["network"],
        "capability": "core_firewall",
        "engage": "EAC0004",
    },
    "lateral_drop": {
        "dataset": "cybersnare.fw.lateral_denied",
        "action": "east_west_drop",
        "category": ["network", "intrusion_detection"],
        "capability": "core_firewall",
        "engage": "EAC0004",
    },
    "containment_violation": {
        "dataset": "cybersnare.fw.containment",
        "action": "containment_violation",
        "category": ["network", "intrusion_detection"],
        "capability": "core_firewall",
        "engage": "EAC0004",
    },
}

# Published address block -> the name the adversary resolves it as.
VIP_SERVICE: dict[str, str] = {
    "203.0.113.10": "www.nexuscorp.example",
    "203.0.113.11": "mail.nexuscorp.example",
    "203.0.113.12": "vpn.nexuscorp.example",
    "203.0.113.20": "dev.nexuscorp.example",
}

# A published address sits in the Internet range but fronts a service
# somewhere else. Zone attribution has to follow the DNAT, otherwise every
# perimeter event looks like internet-to-internet traffic.
VIP_ZONE: dict[str, str] = {
    "203.0.113.10": "dmz",
    "203.0.113.11": "dmz",
    "203.0.113.12": "dmz",
    "203.0.113.20": "deception",
}

ZONE_OF: list[tuple[str, str]] = [
    ("203.0.113.", "internet"),
    ("172.31.10.", "dmz"),
    ("172.31.99.", "transit"),
    ("10.10.20.", "corp"),
    ("10.10.30.", "datacenter"),
    ("10.200.1.", "mgmt"),
    ("10.200.2.", "deception"),
    ("10.200.3.", "egress"),
]

_last: dict[tuple[str, str], int] = {}
_stats = {"polls": 0, "emitted": 0, "errors": 0}


def zone_of(ip: str | None) -> str:
    if not ip:
        return "unknown"
    if ip in VIP_ZONE:
        return VIP_ZONE[ip]
    for prefix, name in ZONE_OF:
        if ip.startswith(prefix):
            return name
    return "external"


def _nft_set(name: str) -> list[dict[str, Any]]:
    """Return the element list of one named set, or [] if it does not exist."""
    proc = subprocess.run(
        ["nft", "-j", "list", "set", "inet", TABLE, name],
        capture_output=True,
        text=True,
        timeout=5,
    )
    if proc.returncode != 0:
        return []
    try:
        doc = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return []
    for block in doc.get("nftables", []):
        if "set" in block:
            return block["set"].get("elem") or []
    return []


def _parse_elem(raw: Any, *, no_port: bool) -> tuple[tuple[str, ...], int] | None:
    """
    Normalise one nft JSON set element into (key_parts, packet_count).

    nft wraps elements that carry statefulness as {"elem": {"val": ..., "counter": ...}}
    and plain elements as the bare value, so both shapes are handled.
    """
    node = raw.get("elem", raw) if isinstance(raw, dict) else raw
    if not isinstance(node, dict):
        return None
    val = node.get("val", node)
    counter = node.get("counter") or {}
    packets = int(counter.get("packets") or 0)

    if isinstance(val, dict) and "concat" in val:
        parts = val["concat"]
    elif isinstance(val, list):
        parts = val
    else:
        parts = [val]

    flat: list[str] = []
    for part in parts:
        if isinstance(part, dict):
            # e.g. {"prefix": {...}} — not expected here, skip the element
            return None
        flat.append(str(part))

    expected = 2 if no_port else 3
    if len(flat) < expected:
        return None
    return tuple(flat[:expected]), packets


def _technique_for(dataset: str, dport: str | None) -> tuple[str, str, str, str]:
    if dataset == "cybersnare.fw.drop":
        return ("T1595.001", "Active Scanning: Scanning IP Blocks", "TA0043", "Reconnaissance")
    if dataset == "cybersnare.fw.icmp":
        return ("T1018", "Remote System Discovery", "TA0007", "Discovery")
    if dataset in ("cybersnare.fw.lateral", "cybersnare.fw.lateral_denied"):
        return ("T1021", "Remote Services", "TA0008", "Lateral Movement")
    if dataset == "cybersnare.fw.containment":
        return ("T1048", "Exfiltration Over Alternative Protocol", "TA0010", "Exfiltration")
    if dport in ("22", "3389"):
        return ("T1021", "Remote Services", "TA0008", "Lateral Movement")
    return ("T1595", "Active Scanning", "TA0043", "Reconnaissance")


async def poll_once() -> int:
    emitted = 0
    for set_name, spec in SET_SPECS.items():
        no_port = bool(spec.get("no_port"))
        for raw in _nft_set(set_name):
            parsed = _parse_elem(raw, no_port=no_port)
            if parsed is None:
                continue
            key, packets = parsed
            ident = (set_name, "|".join(key))
            previous = _last.get(ident, 0)
            if packets <= previous:
                # Counter reset (element timed out and was re-created) still
                # counts as new activity.
                if packets == previous:
                    continue
                delta = packets
            else:
                delta = packets - previous
            _last[ident] = packets

            saddr = key[0]
            daddr = key[1]
            dport = None if no_port else key[2]
            tid, tname, tacid, tacname = _technique_for(spec["dataset"], dport)

            event = new_event(
                dataset=spec["dataset"],
                action=spec["action"],
                category=list(spec["category"]),
                capability=spec["capability"],
                source_ip=saddr,
                dest_ip=daddr,
                dest_port=int(dport) if dport and dport.isdigit() else None,
                dest_service=VIP_SERVICE.get(daddr),
                technique_id=tid,
                technique_name=tname,
                tactic_id=tacid,
                tactic_name=tacname,
                engage_activity=spec["engage"],
            )
            event["firewall"] = {
                "role": ROLE,
                "table": TABLE,
                "set": set_name,
                "packets": delta,
                "packets_total": packets,
                "source_zone": zone_of(saddr),
                "destination_zone": zone_of(daddr),
                "verdict": "accept" if "accept" in set_name else "drop",
            }
            await emit(event)
            emitted += 1
    return emitted


async def poller() -> None:
    # Give the ruleset a moment to settle before the first read.
    await asyncio.sleep(2)
    while True:
        try:
            _stats["polls"] += 1
            _stats["emitted"] += await poll_once()
        except Exception as exc:  # a poll failure must never kill the firewall
            _stats["errors"] += 1
            print(f"fw_agent poll failed: {exc}", flush=True)
        await asyncio.sleep(POLL_S)


def _block(ip: str, ttl_s: int) -> tuple[bool, str]:
    """Add one source address to the nftables blocklist."""
    proc = subprocess.run(
        ["nft", "add", "element", "inet", TABLE, "blocked",
         "{ %s timeout %ds }" % (ip, ttl_s)],
        capture_output=True, text=True, timeout=5,
    )
    return proc.returncode == 0, (proc.stderr or "").strip()


def _unblock(ip: str) -> tuple[bool, str]:
    proc = subprocess.run(
        ["nft", "delete", "element", "inet", TABLE, "blocked", "{ %s }" % ip],
        capture_output=True, text=True, timeout=5,
    )
    return proc.returncode == 0, (proc.stderr or "").strip()


def _blocked_list() -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for raw in _nft_set("blocked"):
        node = raw.get("elem", raw) if isinstance(raw, dict) else {"val": raw}
        if not isinstance(node, dict):
            continue
        val = node.get("val", node)
        counter = node.get("counter") or {}
        out.append({
            "ip": val if isinstance(val, str) else str(val),
            "expires_s": node.get("expires"),
            "packets_dropped": counter.get("packets", 0),
        })
    return out


async def handler(req: dict) -> tuple[int, dict[str, str], bytes]:
    from cs.tinyhttp import json_body

    if req["method"] == "GET" and req["path"] == "/v1/blocked":
        body = json.dumps({"blocked": _blocked_list()}).encode()
        return 200, {"Content-Type": "application/json"}, body

    if req["method"] == "POST" and req["path"] == "/v1/block":
        try:
            payload = json_body(req)
        except Exception:
            return 400, {"Content-Type": "text/plain"}, b"invalid json\n"
        ip = (payload or {}).get("ip")
        if not isinstance(ip, str) or not ip:
            return 400, {"Content-Type": "text/plain"}, b"ip required\n"
        ttl = int((payload or {}).get("ttl_s") or 21600)
        ok, err = _block(ip, ttl)
        _stats["blocked"] = _stats.get("blocked", 0) + (1 if ok else 0)
        if ok:
            print(f"fw_agent blocked {ip} for {ttl}s", flush=True)
        return (
            (200 if ok else 500),
            {"Content-Type": "application/json"},
            json.dumps({"ok": ok, "ip": ip, "ttl_s": ttl, "error": err or None}).encode(),
        )

    if req["method"] == "POST" and req["path"] == "/v1/unblock":
        try:
            payload = json_body(req)
        except Exception:
            return 400, {"Content-Type": "text/plain"}, b"invalid json\n"
        ip = (payload or {}).get("ip")
        if not isinstance(ip, str) or not ip:
            return 400, {"Content-Type": "text/plain"}, b"ip required\n"
        ok, err = _unblock(ip)
        return (
            (200 if ok else 500),
            {"Content-Type": "application/json"},
            json.dumps({"ok": ok, "ip": ip, "error": err or None}).encode(),
        )

    if req["method"] == "GET" and req["path"] == "/health":
        body = json.dumps({"ok": True, "role": ROLE, "table": TABLE, **_stats}).encode()
        return 200, {"Content-Type": "application/json"}, body
    if req["method"] == "GET" and req["path"] == "/v1/ruleset":
        proc = subprocess.run(["nft", "list", "ruleset"], capture_output=True, text=True)
        return 200, {"Content-Type": "text/plain"}, proc.stdout.encode()
    return 404, {"Content-Type": "text/plain"}, b"not found\n"


async def main() -> None:
    print(f"fw_agent starting: role={ROLE} table={TABLE} poll={POLL_S}s", flush=True)
    asyncio.create_task(poller())
    server = await serve(BIND, PORT, handler, name=f"fw-{ROLE}")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
