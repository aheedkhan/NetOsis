#!/usr/bin/env python3
"""NetOsis node agent: reports this node's live state to the SOC controller.

Runs on every lab node (honeypot CTs, the SOC VM) as its own unprivileged
systemd service. Design rules:

* Push only. It opens no listening socket, so nothing (attacker or outsider)
  can connect to it. It only makes outbound HTTP POSTs to the controller.
* Read only. Everything comes from /proc, os.statvfs and `systemctl is-active`.
  It never executes anything it receives; the controller's reply is ignored.
* Stdlib only, so it runs on the system python3 with no venv.
* Never fatal. A controller outage just means the next report is tried later.

Config (environment, normally /etc/netosis/agent.env, root:root 0600, read by systemd):
    NETOSIS_CONTROLLER_URL   http://192.168.40.31:8000
    NETOSIS_INGEST_TOKEN     same token the honeypots use
    NETOSIS_NODE_NAME        ent-web-01 (default: hostname)
    NETOSIS_NODE_ROLE        honeypot | soc | other
    NETOSIS_NODE_CTID        102 (optional)
    NETOSIS_AGENT_SERVICES   netosis-ssh,ollama (systemd units to report)
    NETOSIS_AGENT_INTERVAL   10 (seconds)
"""

from __future__ import annotations

import json
import os
import socket
import struct
import subprocess
import sys
import time
import urllib.request
from typing import Any

VERSION = "1"
TCP_STATES = {"01": "ESTABLISHED", "0A": "LISTEN"}


# ----------------------------------------------------------------------------- /proc readers

def _read(path: str) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def _hex_ip(h: str) -> str:
    if len(h) == 8:
        return socket.inet_ntop(socket.AF_INET, struct.pack("<I", int(h, 16)))
    raw = bytes.fromhex(h)
    # /proc stores IPv6 as four little-endian 32-bit words
    words = b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4))
    ip = socket.inet_ntop(socket.AF_INET6, words)
    return ip[7:] if ip.startswith("::ffff:") else ip


def tcp_sockets() -> list[dict[str, Any]]:
    out = []
    for path in ("/proc/net/tcp", "/proc/net/tcp6"):
        for line in _read(path).splitlines()[1:]:
            parts = line.split()
            if len(parts) < 4 or parts[3] not in TCP_STATES:
                continue
            lip, lport = parts[1].split(":")
            rip, rport = parts[2].split(":")
            out.append({"state": TCP_STATES[parts[3]], "lip": _hex_ip(lip), "lport": int(lport, 16),
                        "rip": _hex_ip(rip), "rport": int(rport, 16)})
    return out


def connections() -> dict[str, Any]:
    socks = tcp_sockets()
    listening = sorted({s["lport"] for s in socks if s["state"] == "LISTEN"})
    flows: dict[tuple[str, str, int], int] = {}
    for s in socks:
        if s["state"] != "ESTABLISHED" or s["rip"] in ("127.0.0.1", "::1"):
            continue
        if s["lport"] in listening:  # someone connected to us
            key = ("in", s["rip"], s["lport"])
        else:  # we connected out
            key = ("out", s["rip"], s["rport"])
        flows[key] = flows.get(key, 0) + 1
    return {
        "listening": listening,
        "flows": [{"dir": d, "peer": ip, "port": port, "count": n} for (d, ip, port), n in sorted(flows.items())],
    }


class CpuMeter:
    def __init__(self) -> None:
        self.prev = self._sample()

    @staticmethod
    def _sample() -> tuple[int, int]:
        fields = (_read("/proc/stat").splitlines() or ["cpu 0"])[0].split()[1:]
        vals = [int(x) for x in fields] or [0]
        idle = vals[3] + (vals[4] if len(vals) > 4 else 0) if len(vals) > 3 else 0
        return sum(vals), idle

    def percent(self) -> float:
        total, idle = self._sample()
        dt, di = total - self.prev[0], idle - self.prev[1]
        self.prev = (total, idle)
        return round(100.0 * (1 - di / dt), 1) if dt > 0 else 0.0


class NetMeter:
    def __init__(self) -> None:
        self.prev = (time.monotonic(), self._sample())

    @staticmethod
    def _sample() -> tuple[int, int]:
        rx = tx = 0
        for line in _read("/proc/net/dev").splitlines()[2:]:
            name, _, rest = line.partition(":")
            if name.strip() == "lo":
                continue
            f = rest.split()
            if len(f) >= 9:
                rx += int(f[0])
                tx += int(f[8])
        return rx, tx

    def rates(self) -> dict[str, int]:
        now, (rx, tx) = time.monotonic(), self._sample()
        t0, (rx0, tx0) = self.prev
        self.prev = (now, (rx, tx))
        dt = max(now - t0, 1e-6)
        return {"rx_bps": int(max(rx - rx0, 0) / dt), "tx_bps": int(max(tx - tx0, 0) / dt)}


def memory() -> dict[str, int]:
    info = {}
    for line in _read("/proc/meminfo").splitlines():
        k, _, v = line.partition(":")
        if v.strip():
            info[k] = int(v.split()[0]) * 1024
    total = info.get("MemTotal", 0)
    avail = info.get("MemAvailable", info.get("MemFree", 0))
    return {"total": total, "used": max(total - avail, 0)}


def disk(path: str = "/") -> dict[str, int]:
    try:
        st = os.statvfs(path)
    except OSError:
        return {"total": 0, "used": 0}
    total = st.f_blocks * st.f_frsize
    return {"total": total, "used": total - st.f_bavail * st.f_frsize}


def addresses() -> list[str]:
    """IPv4 addresses on non-loopback interfaces (no external tools needed)."""
    ips: set[str] = set()
    lines = _read("/proc/net/fib_trie").splitlines()
    for i, line in enumerate(lines):
        if "/32 host LOCAL" in line and i > 0:
            ip = lines[i - 1].split()[-1]
            if not ip.startswith("127."):
                ips.add(ip)
    return sorted(ips)


def default_gateway() -> str | None:
    for line in _read("/proc/net/route").splitlines()[1:]:
        f = line.split()
        if len(f) > 2 and f[1] == "00000000":
            return _hex_ip(f[2])
    return None


def services(names: list[str]) -> dict[str, str]:
    out = {}
    for name in names:
        try:
            r = subprocess.run(["systemctl", "is-active", name], capture_output=True, text=True, timeout=3)
            out[name] = r.stdout.strip() or "unknown"
        except (OSError, subprocess.SubprocessError):
            out[name] = "unknown"
    return out


# ----------------------------------------------------------------------------- report loop

def build_report(cfg: dict[str, Any], cpu: CpuMeter, net: NetMeter) -> dict[str, Any]:
    load = (_read("/proc/loadavg").split() or ["0", "0", "0"])[:3]
    up = _read("/proc/uptime").split()
    return {
        "agent": {"name": cfg["name"], "role": cfg["role"], "ctid": cfg["ctid"], "version": VERSION},
        "ts": time.time(),
        "host": {
            "hostname": socket.gethostname(),
            "addresses": addresses(),
            "gateway": default_gateway(),
            "uptime_s": int(float(up[0])) if up else 0,
            "load": [float(x) for x in load],
            "cpu_pct": cpu.percent(),
            "cpus": os.cpu_count() or 1,
            "mem": memory(),
            "disk": disk("/"),
            "net": net.rates(),
        },
        "services": services(cfg["services"]),
        "tcp": connections(),
    }


def post(cfg: dict[str, Any], body: dict[str, Any]) -> bool:
    req = urllib.request.Request(
        cfg["url"] + "/v1/agent",
        data=json.dumps(body).encode(),
        method="POST",
        headers={"Content-Type": "application/json", "X-Netosis-Token": cfg["token"]},
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            resp.read(256)  # reply is never acted on
        return True
    except Exception as exc:  # noqa: BLE001 — controller down is normal, never fatal
        print(f"[agent] report failed: {exc}", flush=True)
        return False


def config() -> dict[str, Any]:
    ctid = os.environ.get("NETOSIS_NODE_CTID", "").strip()
    return {
        "url": os.environ.get("NETOSIS_CONTROLLER_URL", "http://192.168.40.31:8000").rstrip("/"),
        "token": os.environ.get("NETOSIS_INGEST_TOKEN", ""),
        "name": os.environ.get("NETOSIS_NODE_NAME") or socket.gethostname(),
        "role": os.environ.get("NETOSIS_NODE_ROLE", "other"),
        "ctid": int(ctid) if ctid.isdigit() else None,
        "services": [s for s in os.environ.get("NETOSIS_AGENT_SERVICES", "").split(",") if s.strip()],
        "interval": max(3.0, float(os.environ.get("NETOSIS_AGENT_INTERVAL", "10"))),
    }


def main(argv: list[str]) -> int:
    cfg = config()
    cpu, net = CpuMeter(), NetMeter()
    if "--once" in argv:
        print(json.dumps(build_report(cfg, cpu, net), indent=2))
        return 0
    if not cfg["token"]:
        print("[agent] NETOSIS_INGEST_TOKEN not set; the controller will refuse reports", flush=True)
    print(f"[agent] {cfg['name']} ({cfg['role']}) -> {cfg['url']} every {cfg['interval']:.0f}s", flush=True)
    time.sleep(1)  # first CPU/net delta
    while True:
        post(cfg, build_report(cfg, cpu, net))
        time.sleep(cfg["interval"])


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
