"""Intelligence plane — timelines, profiles, milestone analytics."""

from __future__ import annotations

import json
from collections import Counter, defaultdict, deque
from datetime import datetime
from pathlib import Path
from typing import Any

from cs.mappings import enrich_event

_EVENT_CACHE: dict[str, Any] = {}


def load_events_tail(path: Path, limit: int) -> list[dict[str, Any]]:
    """Read only the last N JSONL lines (fast seek-from-end)."""
    if not path.exists() or limit <= 0:
        return []
    try:
        size = path.stat().st_size
    except OSError:
        return []
    if size == 0:
        return []

    chunk = 512 * 1024
    raw_lines: list[str] = []
    with path.open("rb") as fh:
        pos = size
        carry = b""
        while pos > 0 and len(raw_lines) < limit:
            read_sz = min(chunk, pos)
            pos -= read_sz
            fh.seek(pos)
            block = fh.read(read_sz) + carry
            parts = block.split(b"\n")
            carry = parts[0]
            for part in reversed(parts[1:]):
                line = part.strip()
                if not line:
                    continue
                raw_lines.append(line.decode("utf-8", errors="replace"))
                if len(raw_lines) >= limit:
                    break
        if carry.strip() and len(raw_lines) < limit:
            raw_lines.append(carry.strip().decode("utf-8", errors="replace"))

    raw_lines.reverse()
    events: list[dict[str, Any]] = []
    for line in raw_lines[-limit:]:
        try:
            events.append(enrich_event(json.loads(line)))
        except json.JSONDecodeError:
            continue
    return events


def load_events_cached(path: Path, limit: int | None = 15_000) -> list[dict[str, Any]]:
    """Cached tail load — one disk read per file change."""
    try:
        mtime = path.stat().st_mtime if path.exists() else -1.0
    except OSError:
        mtime = -1.0
    key = f"{path.resolve()}:{limit}"
    entry = _EVENT_CACHE.get(key)
    if entry and entry.get("mtime") == mtime:
        return entry["events"]

    if limit:
        events = load_events_tail(path, limit)
    else:
        events = load_events(path)
    _EVENT_CACHE[key] = {"mtime": mtime, "events": events}
    return events


def load_events(path: Path, limit: int | None = None) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    events: list[dict[str, Any]] = []
    with path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(enrich_event(json.loads(line)))
            except json.JSONDecodeError:
                continue
    if limit:
        return events[-limit:]
    return events


def actor_profile(events: list[dict], actor_key: str) -> dict[str, Any]:
    mine = [e for e in events if (e.get("session") or {}).get("actor_key") == actor_key]
    if not mine:
        return {"actor_key": actor_key, "events": 0}
    techniques: Counter[str] = Counter()
    engage: Counter[str] = Counter()
    datasets: Counter[str] = Counter()
    ips: set[str] = set()
    levels: Counter[str] = Counter()
    commands: list[str] = []
    first = last = mine[0].get("@timestamp")
    for e in mine:
        ts = e.get("@timestamp")
        if ts:
            first = min(first, ts) if first else ts
            last = max(last, ts) if last else ts
        ds = (e.get("event") or {}).get("dataset", "")
        datasets[ds] += 1
        tid = ((e.get("threat") or {}).get("technique") or {}).get("id")
        if tid:
            techniques[tid] += 1
        ea = (e.get("deception") or {}).get("engage_activity")
        if ea:
            engage[ea] += 1
        ip = (e.get("source") or {}).get("ip")
        if ip:
            ips.add(ip)
        lvl = (e.get("session") or {}).get("level")
        if lvl:
            levels[lvl] += 1
        cmd = ((e.get("extra") or {}).get("shell") or {}).get("command")
        if cmd:
            commands.append(cmd)
    return {
        "actor_key": actor_key,
        "events": len(mine),
        "first_seen": first,
        "last_seen": last,
        "linked_ips": sorted(ips),
        "datasets": dict(datasets.most_common()),
        "techniques": dict(techniques.most_common()),
        "engage_activities": dict(engage.most_common()),
        "levels": dict(levels),
        "commands": commands[-50:],
        "timeline": timeline(mine),
    }


def timeline(events: list[dict], max_items: int = 200) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for e in events[-max_items:]:
        ev = e.get("event") or {}
        out.append(
            {
                "timestamp": e.get("@timestamp"),
                "dataset": ev.get("dataset"),
                "action": ev.get("action"),
                "actor_key": (e.get("session") or {}).get("actor_key"),
                "arm": (e.get("session") or {}).get("arm"),
                "level": (e.get("session") or {}).get("level"),
                "source_ip": (e.get("source") or {}).get("ip"),
                "technique": ((e.get("threat") or {}).get("technique") or {}).get("id"),
                "engage": (e.get("deception") or {}).get("engage_activity"),
            }
        )
    return out


def arm_summary(events: list[dict]) -> dict[str, Any]:
    by_arm: dict[str, list[dict]] = defaultdict(list)
    for e in events:
        arm = (e.get("session") or {}).get("arm") or "?"
        by_arm[arm].append(e)
    summary = {}
    for arm, evs in by_arm.items():
        actors = {(e.get("session") or {}).get("actor_key") for e in evs}
        transitions = sum(
            1
            for e in evs
            if (e.get("event") or {}).get("dataset") == "cybersnare.decision.transition"
        )
        shell_cmds = sum(
            1 for e in evs if (e.get("event") or {}).get("dataset") == "cybersnare.shell.command"
        )
        summary[arm] = {
            "events": len(evs),
            "actors": len(actors - {None}),
            "transitions": transitions,
            "shell_commands": shell_cmds,
            "datasets": dict(
                Counter((e.get("event") or {}).get("dataset") for e in evs).most_common(12)
            ),
        }
    return summary


def _parse_ts(ts: str) -> datetime | None:
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None


def _dataset_family(dataset: str) -> str:
    if not dataset:
        return "other"
    parts = dataset.split(".")
    if len(parts) >= 2:
        fam = parts[1]
        if fam.startswith("zeek"):
            return "zeek"
        return fam
    return "other"


def event_volume_series(
    events: list[dict], *, bucket_seconds: int = 300, max_buckets: int = 48
) -> list[dict[str, Any]]:
    """Time-bucketed event volume for SIEM area charts."""
    buckets: dict[int, Counter[str]] = defaultdict(Counter)
    for e in events:
        ts = e.get("@timestamp")
        if not ts:
            continue
        dt = _parse_ts(ts)
        if not dt:
            continue
        epoch = int(dt.timestamp())
        bucket = (epoch // bucket_seconds) * bucket_seconds
        ds = (e.get("event") or {}).get("dataset", "")
        fam = _dataset_family(ds)
        buckets[bucket]["total"] += 1
        buckets[bucket][fam] += 1

    keys = sorted(buckets.keys())[-max_buckets:]
    out: list[dict[str, Any]] = []
    for key in keys:
        row: dict[str, Any] = {
            "ts": key,
            "time": datetime.utcfromtimestamp(key).strftime("%H:%M"),
            "total": buckets[key]["total"],
        }
        for fam in ("zeek", "http", "ssh", "shell", "sinkhole", "decision", "other"):
            if buckets[key][fam]:
                row[fam] = buckets[key][fam]
        out.append(row)
    return out


def top_actors(events: list[dict], limit: int = 12) -> list[dict[str, Any]]:
    counts: Counter[str] = Counter()
    last_seen: dict[str, str] = {}
    levels: dict[str, str] = {}
    techniques: dict[str, Counter[str]] = defaultdict(Counter)
    arms: dict[str, str] = {}

    for e in events:
        ak = (e.get("session") or {}).get("actor_key")
        if not ak:
            continue
        counts[ak] += 1
        ts = e.get("@timestamp")
        if ts:
            last_seen[ak] = ts
        lvl = (e.get("session") or {}).get("level")
        if lvl:
            levels[ak] = lvl
        arm = (e.get("session") or {}).get("arm")
        if arm:
            arms[ak] = arm
        tid = ((e.get("threat") or {}).get("technique") or {}).get("id")
        if tid:
            techniques[ak][tid] += 1

    out: list[dict[str, Any]] = []
    for ak, n in counts.most_common(limit):
        top_tech = techniques[ak].most_common(1)
        out.append(
            {
                "actor_key": ak,
                "events": n,
                "last_seen": last_seen.get(ak),
                "level": levels.get(ak, "—"),
                "arm": arms.get(ak, "?"),
                "top_technique": top_tech[0][0] if top_tech else None,
            }
        )
    return out


def siem_analytics(events: list[dict]) -> dict[str, Any]:
    """Chart-ready aggregates for the intelligence dashboard."""
    return {
        "volume": event_volume_series(events),
        "top_actors": top_actors(events),
        "levels": dict(
            Counter((e.get("session") or {}).get("level") for e in events if (e.get("session") or {}).get("level"))
        ),
        "transitions": extract_transitions(events),
        "patterns": pattern_analytics(events),
    }


TACTIC_ORDER: list[tuple[str, str]] = [
    ("TA0043", "Reconnaissance"),
    ("TA0001", "Initial Access"),
    ("TA0002", "Execution"),
    ("TA0007", "Discovery"),
    ("TA0005", "Defense Evasion"),
    ("TA0011", "Command & Control"),
    ("TA0008", "Lateral Movement"),
    ("TA0006", "Credential Access"),
]

LEVEL_ORDER = ["L0", "L1", "L2", "L3", "BURN", "?"]


def _event_step_label(e: dict) -> tuple[str, str]:
    ds = (e.get("event") or {}).get("dataset") or ""
    tech = ((e.get("threat") or {}).get("technique") or {}).get("id")
    short = ds.replace("cybersnare.", "").replace("zeek.", "z.")
    return (tech or short or "?"), ds


def kill_chain(events: list[dict]) -> list[dict[str, Any]]:
    counts: Counter[str] = Counter()
    for e in events:
        tac = ((e.get("threat") or {}).get("tactic") or {}).get("id")
        if tac:
            counts[tac] += 1
    return [
        {"id": tid, "name": name, "count": counts.get(tid, 0)}
        for tid, name in TACTIC_ORDER
    ]


def attack_patterns(events: list[dict], *, top_n: int = 8) -> list[dict[str, Any]]:
    """Common ordered technique/dataset chains per actor."""
    by_actor: dict[str, list[dict]] = defaultdict(list)
    for e in events:
        ak = (e.get("session") or {}).get("actor_key")
        if ak:
            by_actor[ak].append(e)

    ngram_counts: Counter[tuple[str, ...]] = Counter()
    ngram_meta: dict[tuple[str, ...], list[dict[str, Any]]] = {}

    for evs in by_actor.values():
        evs.sort(key=lambda x: x.get("@timestamp") or "")
        steps: list[dict[str, Any]] = []
        for e in evs:
            label, ds = _event_step_label(e)
            if label == "?":
                continue
            if steps and steps[-1]["label"] == label:
                continue
            steps.append(
                {
                    "label": label,
                    "dataset": ds,
                    "technique": ((e.get("threat") or {}).get("technique") or {}).get("id"),
                    "technique_name": ((e.get("threat") or {}).get("technique") or {}).get("name"),
                    "tactic": ((e.get("threat") or {}).get("tactic") or {}).get("name"),
                    "level": (e.get("session") or {}).get("level"),
                }
            )

        for length in range(2, min(5, len(steps) + 1)):
            for i in range(len(steps) - length + 1):
                seg = steps[i : i + length]
                key = tuple(s["label"] for s in seg)
                ngram_counts[key] += 1
                if key not in ngram_meta:
                    ngram_meta[key] = seg

    out: list[dict[str, Any]] = []
    for key, count in ngram_counts.most_common(top_n):
        out.append(
            {
                "count": count,
                "steps": ngram_meta[key],
                "signature": " → ".join(key),
            }
        )
    return out


def engage_level_matrix(events: list[dict]) -> dict[str, Any]:
    matrix: dict[str, Counter[str]] = defaultdict(Counter)
    for e in events:
        lvl = (e.get("session") or {}).get("level") or "?"
        ea = (e.get("deception") or {}).get("engage_activity")
        if ea:
            matrix[lvl][ea] += 1
    levels = sorted(matrix.keys(), key=lambda x: LEVEL_ORDER.index(x) if x in LEVEL_ORDER else 99)
    engages = sorted({ea for c in matrix.values() for ea in c})
    cells = [
        {"level": lvl, "engage": ea, "count": matrix[lvl][ea]}
        for lvl in levels
        for ea in engages
        if matrix[lvl][ea]
    ]
    return {"levels": levels, "engages": engages, "cells": cells}


def technique_level_matrix(events: list[dict]) -> dict[str, Any]:
    matrix: dict[str, Counter[str]] = defaultdict(Counter)
    for e in events:
        lvl = (e.get("session") or {}).get("level") or "?"
        tid = ((e.get("threat") or {}).get("technique") or {}).get("id")
        if tid:
            matrix[lvl][tid] += 1
    levels = sorted(matrix.keys(), key=lambda x: LEVEL_ORDER.index(x) if x in LEVEL_ORDER else 99)
    techniques = sorted({t for c in matrix.values() for t in c})
    cells = [
        {"level": lvl, "technique": tid, "count": matrix[lvl][tid]}
        for lvl in levels
        for tid in techniques
        if matrix[lvl][tid]
    ]
    return {"levels": levels, "techniques": techniques, "cells": cells}


def dataset_flow(events: list[dict]) -> list[dict[str, Any]]:
    """Telemetry family transitions (recon → auth → shell → sinkhole)."""
    by_actor: dict[str, list[dict]] = defaultdict(list)
    for e in events:
        ak = (e.get("session") or {}).get("actor_key")
        if ak:
            by_actor[ak].append(e)

    flow: Counter[tuple[str, str]] = Counter()
    for evs in by_actor.values():
        evs.sort(key=lambda x: x.get("@timestamp") or "")
        prev: str | None = None
        for e in evs:
            ds = (e.get("event") or {}).get("dataset") or ""
            fam = _dataset_family(ds)
            if prev and prev != fam:
                flow[(prev, fam)] += 1
            prev = fam

    return [
        {"from": a, "to": b, "count": c}
        for (a, b), c in flow.most_common(14)
    ]


def pattern_analytics(events: list[dict]) -> dict[str, Any]:
    return {
        "kill_chain": kill_chain(events),
        "attack_patterns": attack_patterns(events),
        "engage_matrix": engage_level_matrix(events),
        "technique_matrix": technique_level_matrix(events),
        "dataset_flow": dataset_flow(events),
    }


MACHINE_ALIASES: dict[str, str] = {
    "10.200.3.50": "Kali (egress)",
    "10.200.2.50": "Kali attacker",
    "10.200.1.20": "Zeek sensor",
    "10.200.1.14": "Intelligence",
    "10.200.1.11": "Decision plane",
    "10.200.1.10": "Logger",
}

SURFACE_IDS = ("zeek", "ssh", "https", "shell", "sinkhole", "decision")


def _surface_for_dataset(ds: str) -> str:
    if "sinkhole" in ds:
        return "sinkhole"
    if "shell" in ds:
        return "shell"
    if "ssh" in ds:
        return "ssh"
    if "http" in ds:
        return "https"
    if "zeek" in ds:
        return "zeek"
    if "decision" in ds:
        return "decision"
    return "other"


def machine_label(actor_key: str, ip: str | None = None) -> str:
    addr = ip or actor_key.replace("ip:", "")
    if addr in MACHINE_ALIASES:
        return MACHINE_ALIASES[addr]
    if addr.startswith("10.200.3."):
        return f"Egress host .{addr.split('.')[-1]}"
    if addr.startswith("10.200.2."):
        return f"Deception .{addr.split('.')[-1]}"
    if addr.startswith("10.200.1."):
        return f"Mgmt .{addr.split('.')[-1]}"
    return addr or actor_key


def _step_from_event(e: dict, index: int) -> dict[str, Any]:
    ds = (e.get("event") or {}).get("dataset") or ""
    label, _ = _event_step_label(e)
    return {
        "id": f"step:{index}",
        "index": index,
        "timestamp": e.get("@timestamp"),
        "label": label,
        "dataset": ds,
        "action": (e.get("event") or {}).get("action"),
        "technique": ((e.get("threat") or {}).get("technique") or {}).get("id"),
        "technique_name": ((e.get("threat") or {}).get("technique") or {}).get("name"),
        "tactic": ((e.get("threat") or {}).get("tactic") or {}).get("name"),
        "engage": (e.get("deception") or {}).get("engage_activity"),
        "level": (e.get("session") or {}).get("level"),
        "surface": _surface_for_dataset(ds),
        "source_ip": (e.get("source") or {}).get("ip"),
    }


def attack_graph_overview(events: list[dict], *, top_machines: int = 18, min_events: int = 2) -> dict[str, Any]:
    """Spider-web overview: machines ↔ deception surfaces."""
    machines: dict[str, dict[str, Any]] = {}
    touch_edges: Counter[tuple[str, str]] = Counter()

    for e in events:
        ak = (e.get("session") or {}).get("actor_key")
        if not ak:
            continue
        ds = (e.get("event") or {}).get("dataset") or ""
        surf = _surface_for_dataset(ds)
        ip = (e.get("source") or {}).get("ip") or ak.replace("ip:", "")

        if ak not in machines:
            machines[ak] = {
                "id": ak,
                "label": machine_label(ak, ip),
                "ip": ip,
                "events": 0,
                "level": None,
                "arm": None,
                "techniques": Counter(),
                "surfaces": Counter(),
                "first_seen": e.get("@timestamp"),
                "last_seen": e.get("@timestamp"),
            }
        m = machines[ak]
        m["events"] += 1
        ts = e.get("@timestamp")
        if ts:
            m["last_seen"] = ts
            if m["first_seen"] and ts < m["first_seen"]:
                m["first_seen"] = ts
        if surf != "other":
            m["surfaces"][surf] += 1
            touch_edges[(ak, f"surface:{surf}")] += 1
        tid = ((e.get("threat") or {}).get("technique") or {}).get("id")
        if tid:
            m["techniques"][tid] += 1
        lvl = (e.get("session") or {}).get("level")
        if lvl:
            m["level"] = lvl
        arm = (e.get("session") or {}).get("arm")
        if arm:
            m["arm"] = arm

    ranked = sorted(machines.values(), key=lambda x: x["events"], reverse=True)
    ranked = [m for m in ranked if m["events"] >= min_events][:top_machines]
    allowed = {m["id"] for m in ranked}

    nodes: list[dict[str, Any]] = [
        {"id": "surface:core", "label": "CyberSnare", "type": "core", "events": len(events)},
    ]
    for sid in SURFACE_IDS:
        nodes.append({"id": f"surface:{sid}", "label": sid.upper(), "type": "surface"})

    for m in ranked:
        top_tech = m["techniques"].most_common(1)
        nodes.append(
            {
                "id": m["id"],
                "label": m["label"],
                "type": "machine",
                "ip": m["ip"],
                "events": m["events"],
                "level": m.get("level"),
                "arm": m.get("arm"),
                "top_technique": top_tech[0][0] if top_tech else None,
                "surfaces": dict(m["surfaces"].most_common(6)),
                "first_seen": m.get("first_seen"),
                "last_seen": m.get("last_seen"),
            }
        )

    edges: list[dict[str, Any]] = []
    for (ak, surf_id), weight in touch_edges.most_common(120):
        if ak not in allowed:
            continue
        edges.append({"from": ak, "to": surf_id, "weight": weight, "type": "touches"})
        edges.append({"from": surf_id, "to": "surface:core", "weight": max(1, weight // 3), "type": "feeds"})

    # machine ↔ machine co-activity (shared surface touch)
    co_touch: Counter[tuple[str, str]] = Counter()
    surface_actors: dict[str, set[str]] = defaultdict(set)
    for ak, surf_id in touch_edges:
        if ak in allowed:
            surface_actors[surf_id].add(ak)
    for actors in surface_actors.values():
        alist = sorted(actors)
        for i, a in enumerate(alist):
            for b in alist[i + 1 :]:
                co_touch[(a, b)] += 1
    for (a, b), w in co_touch.most_common(24):
        if w >= 2:
            edges.append({"from": a, "to": b, "weight": w, "type": "related"})

    return {"nodes": nodes, "edges": edges, "machine_count": len(ranked), "machines": [n for n in nodes if n["type"] == "machine"]}


OPERATION_PHASES: list[dict[str, str]] = [
    {"id": "infiltration", "label": "Infiltration", "subtitle": "Recon & initial access", "color": "#0a84ff"},
    {"id": "execution", "label": "Execution", "subtitle": "Commands & persistence", "color": "#30d158"},
    {"id": "discovery", "label": "Discovery", "subtitle": "Environment mapping", "color": "#bf5af2"},
    {"id": "exfiltration", "label": "Exfiltration / C2", "subtitle": "Callbacks & egress", "color": "#ff453a"},
]

NETWORK_ZONES: list[dict[str, str]] = [
    {"id": "attacker", "label": "Attacker host"},
    {"id": "egress", "label": "Egress network", "range": "10.200.3.0/24"},
    {"id": "deception", "label": "Deception VLAN", "range": "10.200.2.0/24"},
    {"id": "honeypot", "label": "Honeypot target", "range": "10.200.2.10"},
]


def _zone_for_ip(ip: str) -> str:
    if ip.startswith("10.200.3."):
        return "egress"
    if ip in ("10.200.2.10", "10.200.2.11"):
        return "honeypot"
    if ip.startswith("10.200.2."):
        return "deception"
    if ip.startswith("10.200.1."):
        return "deception"
    return "attacker"


def _phase_for_step(step: dict[str, Any]) -> str:
    ds = step.get("dataset") or ""
    surf = step.get("surface") or ""
    tech = step.get("technique") or step.get("label") or ""
    if surf == "sinkhole" or tech in ("T1071", "T1105"):
        return "exfiltration"
    if tech in ("T1497", "T1007") or "vm_check" in ds or "proc_read" in ds:
        return "discovery"
    if surf == "shell" or tech == "T1059":
        return "execution"
    return "infiltration"


def _flow_type(phase: str) -> str:
    if phase == "exfiltration":
        return "exfiltration"
    if phase == "infiltration":
        return "infiltration"
    return "lateral"


def _build_operation_map(label: str, ip: str, steps: list[dict[str, Any]]) -> dict[str, Any]:
    """Caldera-style phased operation map with infiltration / exfiltration lanes."""
    op_nodes: list[dict[str, Any]] = [
        {
            "id": "attacker",
            "type": "attacker",
            "label": label,
            "ip": ip,
            "zone": _zone_for_ip(ip),
            "phase": "infiltration",
        }
    ]
    op_edges: list[dict[str, Any]] = []
    phase_lane: Counter[str] = Counter()
    prev_id = "attacker"

    for i, step in enumerate(steps):
        phase = _phase_for_step(step)
        lane = phase_lane[phase]
        phase_lane[phase] += 1
        nid = f"op:{i}"
        target_zone = "honeypot" if step.get("surface") in ("ssh", "https", "shell", "sinkhole") else _zone_for_ip(ip)
        op_nodes.append(
            {
                "id": nid,
                "type": "operation",
                "phase": phase,
                "lane": lane,
                "label": step["label"],
                "technique_name": step.get("technique_name"),
                "tactic": step.get("tactic"),
                "surface": step.get("surface"),
                "level": step.get("level"),
                "engage": step.get("engage"),
                "timestamp": step.get("timestamp"),
                "repeat": step.get("repeat", 1),
                "index": i + 1,
                "zone": target_zone,
            }
        )
        op_edges.append(
            {
                "from": prev_id,
                "to": nid,
                "type": _flow_type(phase),
                "order": i + 1,
                "phase": phase,
                "label": step.get("technique_name") or step.get("label"),
            }
        )
        prev_id = nid

    return {
        "phases": OPERATION_PHASES,
        "zones": NETWORK_ZONES,
        "attacker_zone": _zone_for_ip(ip),
        "nodes": op_nodes,
        "edges": op_edges,
        "phase_counts": dict(Counter(_phase_for_step(s) for s in steps)),
    }


def actor_attack_graph(events: list[dict], actor_key: str, *, max_steps: int = 36) -> dict[str, Any]:
    """Per-machine spider path: ordered steps with arrows."""
    mine = [e for e in events if (e.get("session") or {}).get("actor_key") == actor_key]
    if not mine:
        return {"actor_key": actor_key, "nodes": [], "edges": [], "logs": [], "steps": []}

    mine.sort(key=lambda x: x.get("@timestamp") or "")
    ip = (mine[-1].get("source") or {}).get("ip") or actor_key.replace("ip:", "")
    label = machine_label(actor_key, ip)

    logs = [_step_from_event(e, i) for i, e in enumerate(mine)]
    logs_tail = logs[-80:]

    # condensed path — skip consecutive duplicates
    condensed: list[dict[str, Any]] = []
    for step in logs:
        if condensed and condensed[-1]["label"] == step["label"] and condensed[-1]["surface"] == step["surface"]:
            condensed[-1]["repeat"] = condensed[-1].get("repeat", 1) + 1
            condensed[-1]["last_timestamp"] = step["timestamp"]
            continue
        condensed.append({**step, "repeat": 1})

    if len(condensed) > max_steps:
        stride = max(1, len(condensed) // max_steps)
        condensed = condensed[::stride][:max_steps]

    center_id = f"machine:{actor_key}"
    nodes: list[dict[str, Any]] = [
        {
            "id": center_id,
            "label": label,
            "type": "machine",
            "ip": ip,
            "events": len(mine),
            "level": (mine[-1].get("session") or {}).get("level"),
            "arm": (mine[-1].get("session") or {}).get("arm"),
        }
    ]
    edges: list[dict[str, Any]] = []
    prev = center_id

    for i, step in enumerate(condensed):
        sid = f"path:{i}:{step['label']}"
        step_node = {
            "id": sid,
            "type": "step",
            "label": step["label"],
            "technique_name": step.get("technique_name"),
            "tactic": step.get("tactic"),
            "surface": step.get("surface"),
            "level": step.get("level"),
            "engage": step.get("engage"),
            "timestamp": step.get("timestamp"),
            "repeat": step.get("repeat", 1),
            "index": i + 1,
        }
        nodes.append(step_node)
        edges.append(
            {
                "from": prev,
                "to": sid,
                "type": "sequence",
                "step": i + 1,
                "label": step.get("technique_name") or step.get("surface"),
            }
        )
        prev = sid

    return {
        "actor_key": actor_key,
        "label": label,
        "ip": ip,
        "events": len(mine),
        "nodes": nodes,
        "edges": edges,
        "steps": condensed,
        "logs": logs_tail,
        "operation": _build_operation_map(label, ip, condensed),
    }


LADDER: list[dict[str, str]] = [
    {"id": "L0", "name": "Observe", "engage": "EAC0001", "summary": "Sensor only — surfaces hidden"},
    {"id": "L1", "name": "Attract", "engage": "EAC0003", "summary": "SSH/HTTPS visible, auth closed (recon)"},
    {"id": "L2", "name": "Engage", "engage": "EAC0005", "summary": "Login works — restricted shell + sinkhole egress"},
    {"id": "L3", "name": "Immerse", "engage": "EAC0005", "summary": "Deeper fake network (org deploy)"},
    {"id": "BURN", "name": "Burn", "engage": "EAC0009", "summary": "Surfaces frozen — harvest evidence"},
]


def extract_transitions(events: list[dict]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for e in events:
        if (e.get("event") or {}).get("dataset") != "cybersnare.decision.transition":
            continue
        dec = (e.get("extra") or {}).get("decision") or {}
        out.append(
            {
                "timestamp": e.get("@timestamp"),
                "actor_key": (e.get("session") or {}).get("actor_key"),
                "from_level": dec.get("from_level"),
                "to_level": dec.get("to_level"),
                "rationale": dec.get("rationale"),
                "trigger": dec.get("trigger_dataset"),
            }
        )
    return out[-40:]


def deception_state(events: list[dict], activity: dict[str, Any] | None = None) -> dict[str, Any]:
    """Live deception posture for dashboard ladder + surfaces."""
    activity = activity or {}
    manifest = activity.get("manifest") or {}
    caps = manifest.get("capabilities") or {}
    ssh = caps.get("ssh") or {}
    https = caps.get("https") or {}
    shell = caps.get("shell") or {}
    jsonl_transitions = extract_transitions(events)
    runtime = activity.get("transitions") or []
    merged = jsonl_transitions[-20:]
    if runtime and not merged:
        merged = runtime[-20:]
    return {
        "global_level": manifest.get("level") or "L1",
        "policy": activity.get("policy"),
        "manifest_id": manifest.get("manifest_id"),
        "rationale": manifest.get("rationale"),
        "arm": manifest.get("arm"),
        "ladder": LADDER,
        "surfaces": {
            "ssh": {
                "exposed": bool(ssh.get("exposed")),
                "auth": ssh.get("auth", "closed"),
            },
            "https": {
                "exposed": bool(https.get("exposed")),
                "auth": https.get("auth", "closed"),
            },
            "shell": {
                "exposed": bool(shell.get("exposed")),
                "runtime": shell.get("runtime"),
            },
            "sinkhole": bool((caps.get("sinkhole") or {}).get("exposed")),
        },
        "transitions": merged,
        "actors": activity.get("actors") or [],
        "events_seen": activity.get("events_seen"),
    }


def fetch_decision_activity(host: str, port: int) -> dict[str, Any]:
    import urllib.request

    try:
        raw = urllib.request.urlopen(
            f"http://{host}:{port}/v1/activity", timeout=2
        ).read()
        return json.loads(raw.decode())
    except Exception:
        return {}


def dashboard_bundle(events: list[dict], activity: dict[str, Any] | None = None) -> dict[str, Any]:
    """Single cached payload for the dashboard — one JSONL read per refresh."""
    return {
        "report": milestone_report(events),
        "timeline": timeline(events, max_items=50),
        "analytics": siem_analytics(events),
        "deception": deception_state(events, activity),
    }


def milestone_report(events: list[dict]) -> dict[str, Any]:
    actors = {(e.get("session") or {}).get("actor_key") for e in events} - {None}
    transitions = [
        e
        for e in events
        if (e.get("event") or {}).get("dataset") == "cybersnare.decision.transition"
    ]
    techniques = Counter(
        ((e.get("threat") or {}).get("technique") or {}).get("id")
        for e in events
        if ((e.get("threat") or {}).get("technique") or {}).get("id")
    )
    engage = Counter(
        (e.get("deception") or {}).get("engage_activity")
        for e in events
        if (e.get("deception") or {}).get("engage_activity")
    )
    ts_list = [e.get("@timestamp") for e in events if e.get("@timestamp")]
    return {
        "generated_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "total_events": len(events),
        "unique_actors": len(actors),
        "time_range": {"first": min(ts_list) if ts_list else None, "last": max(ts_list) if ts_list else None},
        "arms": arm_summary(events),
        "manifest_transitions": len(transitions),
        "top_techniques": dict(techniques.most_common(15)),
        "top_engage": dict(engage.most_common(10)),
        "dataset_counts": dict(
            Counter((e.get("event") or {}).get("dataset") for e in events).most_common(20)
        ),
    }
