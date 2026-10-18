"""SOC state: merges everything the honeypots ship and answers the dashboard.

In memory for speed, mirrored to disk so a controller restart keeps history:
  data/soc/events.jsonl   append-only, replayed (last N) on start
  data/soc/state.json     latest profile/graph snapshots + sensor table

Every read takes the same `window` (seconds, None = everything held), so the
KPIs, charts, globe, tables and feed on one screen always describe the same
events. Every figure the dashboard shows is defined in KPI_DEFINITIONS and
computed from stored events only. Batches ingested with "demo": true are
tagged so the UI can label them; they are never presented as live.

Nothing here ever talks back to a honeypot or to an attacker.
"""

from __future__ import annotations

import copy
import ipaddress
import json
import os
import threading
import time
import urllib.request
from collections import Counter, defaultdict, deque
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

from controller import attack_meta, geo, network_map
from deception.runtime.persona import classify

ROOT = Path(__file__).resolve().parents[1]
LEVEL_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
SENSOR_ONLINE_SECONDS = 70  # heartbeat is every 20 s
AGENT_ONLINE_SECONDS = 35  # node agents report every 10 s
MAX_AGENT_FLOWS = 200
SESSION_ACTIVE_SECONDS = 300
MAX_EVENTS = 5000
MAX_RESULT_CHARS = 1500
STARTED = time.time()

HIGH_RISK_TECHNIQUES = {"T1003.008", "T1552.001", "T1552.003", "T1053.003", "T1098.004", "T1021.004",
                        "T1070.002", "T1105", "T1059.004"}
HIGH_RISK_CATEGORIES = {"Canary_interaction", "Lateral_movement", "Payload_transfer", "Persistence",
                        "Credential_attack", "Execution", "FS_delete_sensitive", "FS_create_sensitive"}

KPI_DEFINITIONS = {
    "attacks": "Distinct SSH connections (session IDs) that reached a honeypot, including ones that only failed to log in.",
    "sessions_live": "Shell sessions open right now, as reported by each honeypot's 20-second heartbeat.",
    "sources": "Distinct source IP addresses seen in the window.",
    "commands": "Shell commands attackers typed after logging in.",
    "high_risk": "Events mapped to credential access, persistence, execution, payload transfer, lateral movement or a canary.",
    "deception": "Deception responses the policy engine fired (ladder rungs D01–D07), one per rung per session.",
}

WINDOWS = {"1h": 3600, "24h": 86400, "7d": 7 * 86400, "all": None}


def _now() -> float:
    return time.time()


def _epoch(ts: str) -> float:
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
    except (ValueError, AttributeError):
        return 0.0


def parse_window(raw: str | None) -> int | None:
    if raw is None or raw == "":
        return WINDOWS["24h"]
    if raw in WINDOWS:
        return WINDOWS[raw]
    try:
        v = int(raw)
        return v if v > 0 else None
    except ValueError:
        return WINDOWS["24h"]


def _in_lab(ip: str) -> bool:
    """Inside one of the documented lab VLANs (anything else arrived through the firewall)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in ipaddress.ip_network(v["cidr"]) for v in network_map.VLANS)


def is_high_risk(ev: dict[str, Any]) -> bool:
    if ev.get("event_type") == "lateral_movement":
        return True
    if ev.get("technique") in HIGH_RISK_TECHNIQUES:
        return True
    return (ev.get("extra") or {}).get("risk_category") in HIGH_RISK_CATEGORIES


class SocStore:
    def __init__(self, data_dir: Path | str, *, max_events: int = MAX_EVENTS) -> None:
        self.dir = Path(data_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.events: deque[dict[str, Any]] = deque(maxlen=max_events)
        self.sensors: dict[str, dict[str, Any]] = {}
        self.profiles: dict[tuple[str, str], dict[str, Any]] = {}
        self.graphs: dict[str, dict[str, Any]] = {}
        self.agents: dict[str, dict[str, Any]] = {}  # live only, never persisted
        self.seq = 0
        self.cond = threading.Condition()
        self._events_path = self.dir / "events.jsonl"
        self._state_path = self.dir / "state.json"
        self._last_save = 0.0
        self._ai_cache: tuple[float, dict[str, Any]] | None = None
        self._load()

    # ------------------------------------------------------------------ persistence

    def _load(self) -> None:
        if self._events_path.exists():
            lines = self._events_path.read_text(encoding="utf-8").splitlines()[-self.events.maxlen:]
            for line in lines:
                try:
                    ev = json.loads(line)
                except json.JSONDecodeError:
                    continue
                self.seq = max(self.seq, int(ev.get("seq", 0)))
                self.events.append(ev)
        if self._state_path.exists():
            try:
                raw = json.loads(self._state_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                raw = {}
            self.sensors = raw.get("sensors", {})
            self.graphs = raw.get("graphs", {})
            for key, prof in (raw.get("profiles") or {}).items():
                sensor, _, actor = key.partition("|")
                self.profiles[(sensor, actor)] = prof

    def _save_state(self, *, force: bool = False) -> None:
        now = _now()
        if not force and now - self._last_save < 3:
            return
        self._last_save = now
        blob = {
            "sensors": self.sensors,
            "graphs": self.graphs,
            "profiles": {f"{s}|{a}": p for (s, a), p in self.profiles.items()},
        }
        tmp = self._state_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(blob), encoding="utf-8")
        tmp.replace(self._state_path)

    # ------------------------------------------------------------------ ingest

    def ingest(self, payload: dict[str, Any]) -> int:
        """Accept one batch from a honeypot. Returns number of events stored."""
        sensor = payload.get("sensor") or {}
        name = str(sensor.get("name") or "unknown")[:64]
        demo = bool(payload.get("demo"))
        stored = 0
        with self.cond:
            entry = self.sensors.setdefault(name, {"name": name})
            entry.update(
                ip=str(sensor.get("ip") or entry.get("ip") or ""),
                ctid=sensor.get("ctid") if sensor.get("ctid") is not None else entry.get("ctid"),
                last_seen=_now(),
                demo=demo,
            )
            hb = payload.get("heartbeat")
            if hb:
                entry["started"] = hb.get("started", entry.get("started"))
                entry["sessions"] = int(hb.get("sessions", 0))

            lines = []
            for ev in payload.get("events") or []:
                if not isinstance(ev, dict) or not ev.get("timestamp"):
                    continue
                ev = dict(ev)
                ev["sensor"] = name
                if demo:
                    ev["demo"] = True
                if isinstance(ev.get("result"), str) and len(ev["result"]) > MAX_RESULT_CHARS:
                    ev["result"] = ev["result"][:MAX_RESULT_CHARS] + "…"
                self.seq += 1
                ev["seq"] = self.seq
                ev["_t"] = _epoch(ev["timestamp"])
                self.events.append(ev)
                lines.append(json.dumps({k: v for k, v in ev.items() if k != "_t"}, ensure_ascii=False))
                stored += 1
            if lines:
                with self._events_path.open("a", encoding="utf-8") as fh:
                    fh.write("\n".join(lines) + "\n")

            for prof in payload.get("profiles") or []:
                if isinstance(prof, dict) and prof.get("actor_id"):
                    self.profiles[(name, str(prof["actor_id"]))] = prof
            graph = payload.get("graph")
            if isinstance(graph, dict):
                self.graphs[name] = graph

            self._save_state()
            self.cond.notify_all()
        return stored

    def agent_report(self, payload: dict[str, Any]) -> bool:
        """Store one node-agent report (see agent/netosis_agent.py). Shape-checked, size-capped."""
        agent = payload.get("agent") if isinstance(payload, dict) else None
        if not isinstance(agent, dict) or not agent.get("name"):
            return False
        name = str(agent["name"])[:64]
        host = payload.get("host") if isinstance(payload.get("host"), dict) else {}
        tcp = payload.get("tcp") if isinstance(payload.get("tcp"), dict) else {}
        flows = []
        for f in (tcp.get("flows") or [])[:MAX_AGENT_FLOWS]:
            if isinstance(f, dict) and f.get("dir") in ("in", "out"):
                flows.append({"dir": f["dir"], "peer": str(f.get("peer", ""))[:45],
                              "port": int(f.get("port") or 0), "count": int(f.get("count") or 1)})
        services = payload.get("services") if isinstance(payload.get("services"), dict) else {}

        def num(v: Any, default: float = 0) -> float:
            return v if isinstance(v, (int, float)) else default

        mem, dsk, net = host.get("mem") or {}, host.get("disk") or {}, host.get("net") or {}
        report = {
            "name": name,
            "role": str(agent.get("role") or "other")[:16],
            "ctid": agent.get("ctid") if isinstance(agent.get("ctid"), int) else None,
            "version": str(agent.get("version") or "")[:8],
            "hostname": str(host.get("hostname") or "")[:64],
            "addresses": [str(a)[:45] for a in (host.get("addresses") or [])][:16],
            "gateway": str(host.get("gateway") or "")[:45] or None,
            "uptime_s": int(num(host.get("uptime_s"))),
            "load": [float(num(x)) for x in (host.get("load") or [])][:3],
            "cpu_pct": float(num(host.get("cpu_pct"))),
            "cpus": int(num(host.get("cpus"), 1)),
            "mem": {"total": int(num(mem.get("total"))), "used": int(num(mem.get("used")))},
            "disk": {"total": int(num(dsk.get("total"))), "used": int(num(dsk.get("used")))},
            "net": {"rx_bps": int(num(net.get("rx_bps"))), "tx_bps": int(num(net.get("tx_bps")))},
            "services": {str(k)[:48]: str(v)[:16] for k, v in list(services.items())[:12]},
            "listening": [int(x) for x in (tcp.get("listening") or []) if isinstance(x, int)][:64],
            "flows": flows,
            "demo": bool(payload.get("demo")),
            "last_seen": _now(),
        }
        with self.cond:
            self.agents[name] = report
        return True

    def agents_table(self) -> list[dict[str, Any]]:
        now = _now()
        with self.cond:
            agents = copy.deepcopy(list(self.agents.values()))
        for a in agents:
            a["online"] = now - a["last_seen"] < AGENT_ONLINE_SECONDS
        return sorted(agents, key=lambda a: a["name"])

    # ------------------------------------------------------------------ helpers

    def _events(self, window: int | None) -> list[dict[str, Any]]:
        with self.cond:
            snap = list(self.events)
        for ev in snap:
            if "_t" not in ev:
                ev["_t"] = _epoch(ev.get("timestamp", ""))
        if window is None:
            return snap
        cutoff = _now() - window
        return [e for e in snap if e["_t"] >= cutoff]

    @staticmethod
    def _public(ev: dict[str, Any]) -> dict[str, Any]:
        return {k: v for k, v in ev.items() if k != "_t"}

    def _mode(self, events: Iterable[dict[str, Any]]) -> str:
        flags = {bool(e.get("demo")) for e in events}
        if flags == {True}:
            return "demo"
        if flags == {False}:
            return "live"
        return "mixed" if flags else "empty"

    # ------------------------------------------------------------------ events

    def events_after(self, seq: int = 0, limit: int = 200, *, actor: str | None = None,
                     sensor: str | None = None, window: int | None = None, q: str | None = None,
                     event_type: str | None = None, session: str | None = None) -> list[dict[str, Any]]:
        out = [e for e in self._events(window) if e["seq"] > seq]
        if actor:
            out = [e for e in out if e.get("actor_id") == actor or e.get("source_ip") == actor]
        if sensor:
            out = [e for e in out if e.get("sensor") == sensor]
        if session:
            out = [e for e in out if e.get("session_id") == session]
        if event_type:
            types = set(event_type.split(","))
            out = [e for e in out if e.get("event_type") in types]
        if q:
            ql = q.lower()
            out = [e for e in out if ql in json.dumps(self._public(e)).lower()]
        return [self._public(e) for e in out[-limit:]]

    def wait_for_events(self, after_seq: int, timeout: float = 15.0) -> list[dict[str, Any]]:
        deadline = time.monotonic() + timeout
        with self.cond:
            while self.seq <= after_seq:
                left = deadline - time.monotonic()
                if left <= 0:
                    return []
                self.cond.wait(left)
            return [self._public(e) for e in self.events if e["seq"] > after_seq]

    # ---- actors --------------------------------------------------------------

    def actors(self, window: int | None = None) -> list[dict[str, Any]]:
        events = self._events(window)
        with self.cond:
            profiles = dict(self.profiles)

        by_ip: dict[str, dict[str, Any]] = {}
        for ev in events:
            ip = ev.get("source_ip") or "unknown"
            a = by_ip.get(ip)
            if a is None:
                a = by_ip[ip] = {
                    "id": ev.get("actor_id") or f"actor-{ip}", "ip": ip,
                    "first_seen": ev["timestamp"], "last_seen": ev["timestamp"],
                    "auth_failures": 0, "auth_successes": 0, "usernames": Counter(),
                    "sensors": set(), "hosts": set(), "event_count": 0, "command_count": 0,
                    "techniques": Counter(), "sessions": set(), "deception": [], "demo": False,
                    "high_risk": 0,
                }
            a["last_seen"] = max(a["last_seen"], ev["timestamp"])
            a["first_seen"] = min(a["first_seen"], ev["timestamp"])
            a["event_count"] += 1
            a["sensors"].add(ev.get("sensor", ""))
            a["sessions"].add(ev.get("session_id"))
            a["demo"] = a["demo"] or bool(ev.get("demo"))
            if ev.get("target_host"):
                a["hosts"].add(ev["target_host"])
            et = ev.get("event_type")
            if et == "auth_failure":
                a["auth_failures"] += 1
                if (ev.get("extra") or {}).get("username"):
                    a["usernames"][ev["extra"]["username"]] += 1
            elif et == "auth_success":
                a["auth_successes"] += 1
            elif et == "command":
                a["command_count"] += 1
            elif et == "deception_action":
                act = (ev.get("extra") or {}).get("action")
                if act and act not in a["deception"]:
                    a["deception"].append(act)
            if ev.get("technique") and et != "deception_action":
                a["techniques"][ev["technique"]] += 1
            if is_high_risk(ev):
                a["high_risk"] += 1

        merged: dict[str, dict[str, Any]] = defaultdict(lambda: {
            "commands": [], "categories": [], "risk_score": 0.0, "level": "LOW", "canary_hits": 0,
            "paths_created": [], "packages": [], "sandbox_jobs": 0,
        })
        for (_sensor, _aid), prof in profiles.items():
            ip = prof.get("source_ip") or ""
            if ip not in by_ip:
                continue
            m = merged[ip]
            m["commands"] += [c for c in prof.get("commands", []) if c not in m["commands"]]
            m["categories"] += [c for c in prof.get("categories", []) if c not in m["categories"]]
            m["risk_score"] = max(m["risk_score"], float(prof.get("risk_score") or 0))
            if LEVEL_ORDER.get(prof.get("level", "LOW"), 0) > LEVEL_ORDER[m["level"]]:
                m["level"] = prof["level"]
            m["canary_hits"] += int(prof.get("canary_hits") or 0)
            m["paths_created"] += [p for p in prof.get("paths_created", []) if p not in m["paths_created"]]
            m["packages"] += [p for p in prof.get("packages_attempted", []) if p not in m["packages"]]
            m["sandbox_jobs"] += int(prof.get("sandbox_jobs") or 0)

        out = []
        for ip, a in by_ip.items():
            m = merged.get(ip)
            commands = m["commands"] if m else []
            persona = classify(
                commands, categories=m["categories"] if m else (), packages=m["packages"] if m else (),
                sandbox_jobs=m["sandbox_jobs"] if m else 0, auth_failures=a["auth_failures"],
            )
            risk_score = m["risk_score"] if m else min(a["auth_failures"] * 0.25, 3.0)
            level = m["level"] if m else ("MEDIUM" if a["auth_failures"] >= 10 else "LOW")
            out.append({
                "id": a["id"], "ip": ip, "demo": a["demo"],
                "geo": geo.locate(ip, demo=a["demo"]),
                "first_seen": a["first_seen"], "last_seen": a["last_seen"],
                "persona": persona.to_dict(),
                "risk_score": round(risk_score, 1), "level": level,
                "auth_failures": a["auth_failures"], "auth_successes": a["auth_successes"],
                "usernames": [u for u, _ in a["usernames"].most_common(5)],
                "sensors": sorted(s for s in a["sensors"] if s),
                "hosts": sorted(a["hosts"]),
                "sessions": len([s for s in a["sessions"] if s]),
                "event_count": a["event_count"], "command_count": a["command_count"],
                "high_risk": a["high_risk"],
                "techniques": [t for t, _ in a["techniques"].most_common()],
                "deception": sorted(a["deception"]),
                "recent_commands": commands[-8:],
                "canary_hits": m["canary_hits"] if m else 0,
                "paths_created": (m["paths_created"] if m else [])[-6:],
            })
        out.sort(key=lambda x: (LEVEL_ORDER.get(x["level"], 0), x["last_seen"]), reverse=True)
        return out

    # ---- sessions -------------------------------------------------------------

    def sessions(self, window: int | None = None) -> list[dict[str, Any]]:
        now = _now()
        by_sid: dict[str, dict[str, Any]] = {}
        for ev in self._events(window):
            sid = ev.get("session_id")
            if not sid:
                continue
            s = by_sid.setdefault(sid, {
                "id": sid, "ip": ev.get("source_ip"), "sensor": ev.get("sensor"), "host": ev.get("target_host"),
                "start": ev["timestamp"], "last": ev["timestamp"], "_last_t": ev["_t"],
                "commands": 0, "failed_logins": 0, "logged_in": False, "user": None,
                "techniques": Counter(), "high_risk": 0, "pivot_to": [], "demo": bool(ev.get("demo")),
                "deception": [],
            })
            s["last"] = max(s["last"], ev["timestamp"])
            s["_last_t"] = max(s["_last_t"], ev["_t"])
            et = ev.get("event_type")
            if et == "auth_failure":
                s["failed_logins"] += 1
                s["user"] = s["user"] or (ev.get("extra") or {}).get("username")
            elif et == "auth_success":
                s["logged_in"] = True
                s["user"] = (ev.get("extra") or {}).get("username") or s["user"]
            elif et == "command":
                s["commands"] += 1
            elif et == "lateral_movement" and ev.get("target_host") not in s["pivot_to"]:
                s["pivot_to"].append(ev.get("target_host"))
            elif et == "deception_action":
                act = (ev.get("extra") or {}).get("action")
                if act and act not in s["deception"]:
                    s["deception"].append(act)
            if ev.get("technique") and et not in {"deception_action"}:
                s["techniques"][ev["technique"]] += 1
            if is_high_risk(ev):
                s["high_risk"] += 1
        out = []
        for s in by_sid.values():
            s["active"] = now - s.pop("_last_t") < SESSION_ACTIVE_SECONDS
            s["duration_s"] = max(0, int(_epoch(s["last"]) - _epoch(s["start"])))
            s["techniques"] = [t for t, _ in s["techniques"].most_common()]
            s["outcome"] = "shell" if s["logged_in"] else ("failed login" if s["failed_logins"] else "connected")
            out.append(s)
        out.sort(key=lambda s: s["last"], reverse=True)
        return out

    # ---- alerts --------------------------------------------------------------

    def alerts(self, limit: int = 60, window: int | None = None) -> list[dict[str, Any]]:
        fails: Counter[str] = Counter()
        out: list[dict[str, Any]] = []
        for ev in self._events(window):
            ip = ev.get("source_ip", "")
            et = ev.get("event_type")
            cat = (ev.get("extra") or {}).get("risk_category")
            base = {"seq": ev["seq"], "timestamp": ev["timestamp"], "actor": ev.get("actor_id"),
                    "ip": ip, "sensor": ev.get("sensor"), "host": ev.get("target_host"),
                    "session": ev.get("session_id"), "technique": ev.get("technique"), "demo": bool(ev.get("demo"))}
            if et == "auth_failure":
                fails[ip] += 1
                continue
            if et == "auth_success" and fails[ip] >= 3:
                out.append({**base, "severity": "HIGH", "kind": "login-after-guessing",
                            "title": f"Logged in after {fails[ip]} failed attempts",
                            "detail": f"as {(ev.get('extra') or {}).get('username', '?')} on {ev.get('target_host')}"})
                fails[ip] = 0
            elif et == "lateral_movement":
                src = (ev.get("extra") or {}).get("from_host", "?")
                out.append({**base, "severity": "CRITICAL", "kind": "lateral-movement",
                            "title": f"Lateral movement {src} → {ev.get('target_host')}", "detail": ev.get("command", "")})
            elif et == "deception_action":
                x = ev.get("extra") or {}
                out.append({**base, "severity": "MEDIUM", "kind": "deception",
                            "title": f"Deception {x.get('action')} fired · {str(x.get('name', '')).replace('_', ' ')}",
                            "detail": x.get("reason", "")})
            elif cat == "Canary_interaction":
                out.append({**base, "severity": "CRITICAL", "kind": "canary",
                            "title": "Canary file opened", "detail": ev.get("command", "")})
            elif cat == "Payload_transfer":
                out.append({**base, "severity": "HIGH", "kind": "payload",
                            "title": "Tool or payload transfer", "detail": ev.get("command", "")})
            elif ev.get("technique") in {"T1003.008", "T1552.001", "T1552.003"}:
                out.append({**base, "severity": "HIGH", "kind": "credential",
                            "title": "Credential access", "detail": ev.get("command", "")})
            elif ev.get("technique") in {"T1053.003", "T1098.004"}:
                out.append({**base, "severity": "HIGH", "kind": "persistence",
                            "title": "Persistence attempt", "detail": ev.get("command", "")})
            elif ev.get("technique") == "T1070.002":
                out.append({**base, "severity": "HIGH", "kind": "evasion",
                            "title": "Log tampering", "detail": ev.get("command", "")})
        out.reverse()
        return out[:limit]

    # ---- ATT&CK --------------------------------------------------------------

    def attack(self, window: int | None = None) -> dict[str, Any]:
        techs: dict[str, dict[str, Any]] = {}
        for ev in self._events(window):
            tid = ev.get("technique")
            if not tid or ev.get("event_type") == "deception_action":
                continue
            name, tactic = attack_meta.lookup(tid, ev.get("technique_name"))
            t = techs.setdefault(tid, {"id": tid, "name": name, "tactic": tactic, "count": 0,
                                       "actors": set(), "last_seen": "", "example": "", "commands": Counter()})
            t["count"] += 1
            t["actors"].add(ev.get("source_ip", ""))
            if ev.get("command"):
                t["commands"][ev["command"]] += 1
            if ev["timestamp"] >= t["last_seen"]:
                t["last_seen"] = ev["timestamp"]
                t["example"] = ev.get("command", "")
        columns = []
        for tactic in attack_meta.TACTICS:
            items = [
                {**{k: v for k, v in t.items() if k not in {"actors", "commands"}},
                 "actors": len(t["actors"]), "top_commands": [c for c, _ in t["commands"].most_common(5)]}
                for t in techs.values() if t["tactic"] == tactic
            ]
            items.sort(key=lambda x: -x["count"])
            columns.append({"tactic": tactic, "techniques": items, "count": sum(i["count"] for i in items)})
        supported = sorted(attack_meta.TECHNIQUES.items())
        return {
            "tactics": columns,
            "total_techniques": len(techs),
            "total_events": sum(t["count"] for t in techs.values()),
            "supported": [{"id": k, "name": v[0], "tactic": v[1]} for k, v in supported],
        }

    # ---- geo -----------------------------------------------------------------

    def geo(self, window: int | None = None) -> dict[str, Any]:
        actors = self.actors(window)
        demo_any = any(a["demo"] for a in actors)
        live_site = geo.site(demo=False)
        demo_site = geo.site(demo=True) if demo_any else None
        points, unmapped = [], {"internal": 0, "public_unmapped": 0, "reserved": 0}
        for a in actors:
            g = a["geo"]
            if g.get("mapped"):
                dest = demo_site if a["demo"] else live_site
                points.append({
                    "ip": a["ip"], "lat": g["lat"], "lng": g["lng"], "country": g.get("country"),
                    "iso": g.get("iso"), "city": g.get("city"), "source": g.get("source"), "demo": a["demo"],
                    "level": a["level"], "events": a["event_count"], "sessions": a["sessions"],
                    "persona": a["persona"]["label"], "hosts": a["hosts"], "last_seen": a["last_seen"],
                    "arc": dest is not None,
                    "dest": dest,
                })
            elif g["kind"] == "private":
                unmapped["internal"] += 1
            elif g["kind"] == "public":
                unmapped["public_unmapped"] += 1
            else:
                unmapped["reserved"] += 1
        countries = Counter(p["country"] for p in points if p.get("country"))
        return {
            "points": points, "unmapped": unmapped, "site": live_site, "demo_site": demo_site,
            "countries": [{"country": c, "actors": n} for c, n in countries.most_common()],
            "geodb": geo.geodb_status(),
        }

    # ---- deception -----------------------------------------------------------

    def deception(self, window: int | None = None) -> dict[str, Any]:
        fired = [self._public(e) for e in self._events(window) if e.get("event_type") == "deception_action"]
        counts = Counter((e.get("extra") or {}).get("action") for e in fired)
        policy = load_policy()
        ladder = []
        for step in policy.get("ladder") or []:
            aid = str(step.get("id"))
            meta = (policy.get("actions") or {}).get(aid, {})
            ladder.append({
                "id": aid, "min_score": step.get("min_score"), "name": meta.get("name"),
                "description": meta.get("description"), "fired": counts.get(aid, 0),
                "last": next((e["timestamp"] for e in reversed(fired) if (e.get("extra") or {}).get("action") == aid), None),
            })
        return {"ladder": ladder, "history": list(reversed(fired))[:200], "weights": policy.get("weights") or {},
                "policy_error": policy.get("_error")}

    # ---- graph ---------------------------------------------------------------

    def graph(self, window: int | None = None) -> dict[str, Any]:
        """Actors → hosts → techniques, from events (one edge per relation, weighted)."""
        actors = {a["ip"]: a for a in self.actors(window)}
        events = self._events(window)
        nodes: dict[str, dict[str, Any]] = {}
        edges: dict[tuple[str, str, str], dict[str, Any]] = {}

        for vlan in network_map.VLANS:
            for h in vlan["hosts"]:
                if h["kind"] in {"honeypot"}:
                    nodes[f"host:{h['name']}"] = {"id": f"host:{h['name']}", "type": "honeypot", "label": h["name"],
                                                  "ip": h["ip"], "vlan": vlan["id"], "weight": 0}

        def edge(src: str, dst: str, rel: str) -> None:
            e = edges.setdefault((src, dst, rel), {"source": src, "target": dst, "relation": rel, "weight": 0})
            e["weight"] += 1

        for ip, a in actors.items():
            nodes[f"actor:{ip}"] = {"id": f"actor:{ip}", "type": "actor", "label": ip, "level": a["level"],
                                    "persona": a["persona"]["label"], "weight": a["event_count"], "demo": a["demo"]}
        for ev in events:
            ip = ev.get("source_ip") or "unknown"
            host = f"host:{ev.get('target_host')}"
            if ip not in actors or host not in nodes:
                continue
            nodes[host]["weight"] += 1
            et = ev.get("event_type")
            if et == "lateral_movement":
                src_host = f"host:{(ev.get('extra') or {}).get('from_host')}"
                if src_host in nodes:
                    edge(src_host, host, "lateral")
            elif et in {"auth_failure", "auth_success"}:
                edge(f"actor:{ip}", host, "login" if et == "auth_success" else "guess")
            elif et == "command":
                edge(f"actor:{ip}", host, "session")
            tid = ev.get("technique")
            if tid and et in {"command", "lateral_movement"}:
                name, tactic = attack_meta.lookup(tid, ev.get("technique_name"))
                tnode = nodes.setdefault(f"technique:{tid}", {"id": f"technique:{tid}", "type": "technique",
                                                              "label": tid, "name": name, "tactic": tactic, "weight": 0})
                tnode["weight"] += 1
                edge(host, f"technique:{tid}", "observed")
        return {"nodes": list(nodes.values()), "edges": list(edges.values())}

    # ---- network + health + ai -------------------------------------------------

    def _sensor_table(self) -> list[dict[str, Any]]:
        now = _now()
        with self.cond:
            sensors = copy.deepcopy(self.sensors)
        out = []
        for name in network_map_honeypots():
            s = sensors.get(name) or {}
            online = bool(s and now - s.get("last_seen", 0) < SENSOR_ONLINE_SECONDS)
            out.append({"name": name, "online": online, "sessions": s.get("sessions", 0) if online else 0,
                        "last_seen": s.get("last_seen"), "ctid": s.get("ctid"), "demo": bool(s.get("demo"))})
        return out

    def network(self, window: int | None = None) -> dict[str, Any]:
        sensors = {s["name"]: s for s in self._sensor_table()}
        agents = {a["name"]: a for a in self.agents_table()}
        events = self._events(window)
        hits = Counter(ev.get("target_host") for ev in events)
        pivots = Counter()
        for ev in events:
            if ev.get("event_type") == "lateral_movement":
                pivots[((ev.get("extra") or {}).get("from_host"), ev.get("target_host"))] += 1

        # who is who: documented addresses plus whatever each agent reports for itself
        by_ip: dict[str, str] = {}
        kinds: dict[str, str] = {}
        for vlan in network_map.VLANS:
            for h in vlan["hosts"]:
                by_ip[h["ip"]] = h["name"]
                kinds[h["name"]] = h["kind"]
        for a in agents.values():
            for ip in a["addresses"]:
                by_ip.setdefault(ip, a["name"])

        vlans = []
        for vlan in network_map.VLANS:
            hosts = []
            for h in vlan["hosts"]:
                h = dict(h)
                a = agents.get(h["name"]) or next((x for x in agents.values() if h["ip"] in x["addresses"]), None)
                if a:
                    h["agent"] = {k: a[k] for k in ("online", "last_seen", "uptime_s", "cpu_pct", "cpus", "load",
                                                     "mem", "disk", "net", "services", "listening", "addresses",
                                                     "gateway", "version", "demo")}
                    h["agent"]["connections_in"] = sum(f["count"] for f in a["flows"] if f["dir"] == "in")
                if h["kind"] == "honeypot":
                    s = sensors.get(h["name"], {})
                    agent_on = bool(a and a["online"])
                    h.update(online=bool(s.get("online")) or agent_on, sessions=s.get("sessions", 0),
                             last_seen=max(filter(None, [s.get("last_seen"), a and a["last_seen"]]), default=None))
                elif a:
                    h["online"] = a["online"]
                h["events"] = hits.get(h["name"], 0)
                hosts.append(h)
            vlans.append({**{k: v for k, v in vlan.items() if k != "hosts"}, "hosts": hosts})

        # live TCP flows right now, from online agents; one entry per (from, to, port)
        live: dict[tuple[str, str, int], dict[str, Any]] = {}
        for a in agents.values():
            if not a["online"]:
                continue
            for f in a["flows"]:
                peer = by_ip.get(f["peer"]) or (f["peer"] if _in_lab(f["peer"]) else "outside")
                src, dst = (peer, a["name"]) if f["dir"] == "in" else (a["name"], peer)
                if src == dst:
                    continue
                key = (src, dst, f["port"])
                cur = live.setdefault(key, {"from": src, "to": dst, "port": f["port"], "count": 0,
                                            "peer_ip": f["peer"] if peer == "outside" else None})
                # both ends may report the same TCP connection: keep the larger count, don't add
                cur["count"] = max(cur["count"], f["count"])
        flows = []
        for fl in live.values():
            to_kind, from_kind = kinds.get(fl["to"]), kinds.get(fl["from"])
            if fl["port"] in (8000,) and to_kind == "soc":
                fl["kind"] = "telemetry"
            elif fl["port"] == 11434:
                fl["kind"] = "llm"
            elif from_kind == "honeypot" and to_kind == "honeypot":
                fl["kind"] = "pivot"
            elif to_kind == "honeypot" and fl["port"] in (22, 2222) and fl["from"] not in kinds:
                fl["kind"] = "attack"
            else:
                fl["kind"] = "other"
            flows.append(fl)
        flows.sort(key=lambda f: ("attack", "pivot", "other", "llm", "telemetry").index(f["kind"]))

        return {"edge": network_map.EDGE, "outside": network_map.OUTSIDE, "vlans": vlans,
                "paths": [{"from": a, "to": b, "count": n} for (a, b), n in pivots.items()],
                "entry_events": hits.get("ent-web-01", 0),
                "live_flows": flows,
                "agents": {"online": sum(1 for a in agents.values() if a["online"]), "total": len(agents)}}

    def ai(self, window: int | None = None) -> dict[str, Any]:
        events = [e for e in self._events(window) if e.get("event_type") == "command"]
        llm = [e for e in events if (e.get("extra") or {}).get("llm_fallback")]
        now = _now()
        if self._ai_cache is None or now - self._ai_cache[0] > 15:
            base = os.environ.get("NETOSIS_LLM_BASE_URL", "http://127.0.0.1:11434/v1").rstrip("/")
            base = base[:-3] if base.endswith("/v1") else base
            status: dict[str, Any] = {"url": base, "reachable": False, "models": []}
            try:
                with urllib.request.urlopen(f"{base}/api/tags", timeout=2) as r:
                    data = json.loads(r.read())
                status["reachable"] = True
                status["models"] = [m.get("name") for m in data.get("models", [])]
            except Exception as exc:  # Ollama down or not on this VM
                status["error"] = str(exc)[:160]
            self._ai_cache = (now, status)
        return {
            "ollama": self._ai_cache[1],
            "model": os.environ.get("NETOSIS_LLM_MODEL", "qwen2.5:0.5b"),
            "commands": len(events), "llm_answered": len(llm),
            "deterministic": len(events) - len(llm),
            "recent_llm": [{"ts": e["timestamp"], "command": e.get("command"), "sensor": e.get("sensor")} for e in llm[-12:]][::-1],
        }

    def health(self) -> dict[str, Any]:
        sensors = self._sensor_table()
        return {
            "controller": {"uptime_s": int(_now() - STARTED), "events_stored": len(self.events),
                           "events_total": self.seq, "max_events": self.events.maxlen},
            "sensors": sensors,
            "agents": self.agents_table(),
            "geodb": geo.geodb_status(),
            "site_configured": geo.site(demo=False) is not None,
            "ingest_token_set": bool(os.environ.get("NETOSIS_INGEST_TOKEN")),
            "proxmox_configured": bool(os.environ.get("PROXMOX_TOKEN_ID") and os.environ.get("PROXMOX_TOKEN_SECRET")),
        }

    def overview(self, window: int | None = None) -> dict[str, Any]:
        now = _now()
        events = self._events(window)
        sensors = self._sensor_table()
        alerts = self.alerts(1000, window)
        # time series: 24 buckets across the window (or the last 24 h for "all")
        span = window or max(3600, int(now - min((e["_t"] for e in events), default=now)))
        step = span / 24
        series = {"all": [0] * 24, "high": [0] * 24}
        for ev in events:
            idx = int((ev["_t"] - (now - span)) // step)
            if 0 <= idx < 24:
                series["all"][idx] += 1
                if is_high_risk(ev):
                    series["high"][idx] += 1
        actors = self.actors(window)
        levels = Counter(a["level"] for a in actors)

        def counts(evs: list[dict[str, Any]]) -> dict[str, int]:
            return {
                "attacks": len({e.get("session_id") for e in evs if e.get("session_id")}),
                "sources": len({e.get("source_ip") for e in evs}),
                "commands": sum(1 for e in evs if e.get("event_type") == "command"),
                "high_risk": sum(1 for e in evs if is_high_risk(e)),
                "deception": sum(1 for e in evs if e.get("event_type") == "deception_action"),
            }

        # Same-length window immediately before this one, for "vs previous" trends.
        # None when the window is unbounded or history doesn't reach back that far.
        previous = None
        if window:
            with self.cond:
                snap = list(self.events)
            oldest = min((e.get("_t") or _epoch(e.get("timestamp", "")) for e in snap), default=now)
            if oldest <= now - 2 * window:
                prev = [e for e in snap if now - 2 * window <= (e.get("_t") or 0) < now - window]
                previous = counts(prev)
        return {
            "now": now, "window": window, "mode": self._mode(events),
            "kpis": {
                **counts(events),
                "sessions_live": sum(s["sessions"] for s in sensors if s["online"]),
            },
            "previous": previous,
            "definitions": KPI_DEFINITIONS,
            "risk": {lvl: levels.get(lvl, 0) for lvl in ("CRITICAL", "HIGH", "MEDIUM", "LOW")},
            "series": {**series, "step_s": int(step), "start": now - span},
            "sensors": sensors,
            "sensors_online": sum(1 for s in sensors if s["online"]),
            "sensors_total": len(sensors),
            "alerts_total": len(alerts),
            "critical": sum(1 for a in alerts if a["severity"] == "CRITICAL"),
        }


def network_map_honeypots() -> list[str]:
    return [h["name"] for v in network_map.VLANS for h in v["hosts"] if h["kind"] == "honeypot"]


def load_policy() -> dict[str, Any]:
    path = ROOT / "policy" / "rules" / "baseline.yml"
    try:
        import yaml  # present on honeypots; on the SOC VM: apt install python3-yaml
    except ImportError:
        return {"_error": "python3-yaml not installed on the controller"}
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except OSError as exc:
        return {"_error": str(exc)}
