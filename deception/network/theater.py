"""Network theater: nmap / ping / nc / telnet / curl / DNS / arp answers.

Everything here is computed from deception/lore/topology.yml plus the
current host — nothing ever touches a real socket. Scans, pings and SSH
banners always agree with each other and with the honeypot's own ps/ss
output, because they all read the same topology file.

`resolve_ssh_target()` only answers "does this host exist, and is it a real
pivot sensor" — the actual relay connection (when it is) is made by the SSH
front-door (scripts/ssh_honeypot.py), not here.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml

from deception.system import clock

if TYPE_CHECKING:
    from deception.runtime.host import Session

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_TOPOLOGY = ROOT / "deception" / "lore" / "topology.yml"
NMAP_VERSION = "7.80"


@dataclass
class FakeHost:
    ip: str
    hostname: str
    os: str = "linux"
    icmp: bool = False
    pivot: bool = False
    ctid: int | None = None
    ssh_deny: bool = False
    default_state: str = "closed"
    ports: list[dict[str, Any]] = field(default_factory=list)
    http: dict[str, Any] = field(default_factory=dict)

    @property
    def fqdn(self) -> str:
        return self.hostname if "." in self.hostname else f"{self.hostname}.corp.local"


@dataclass
class Topology:
    domain: str
    subnets: list[dict[str, Any]]
    hosts: dict[str, FakeHost]

    def find(self, needle: str) -> FakeHost | None:
        needle = needle.strip().rstrip(".")
        if needle in self.hosts:
            return self.hosts[needle]
        for h in self.hosts.values():
            if h.hostname == needle or h.fqdn == needle or h.hostname == needle.split(".")[0]:
                return h
        return None

    def subnet_of(self, ip: str) -> dict[str, Any] | None:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        for sub in self.subnets:
            if addr in ipaddress.ip_network(sub["cidr"]):
                return sub
        return None


@lru_cache(maxsize=2)
def load_topology(path_str: str = str(DEFAULT_TOPOLOGY)) -> Topology:
    with Path(path_str).open(encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}
    hosts: dict[str, FakeHost] = {}
    for entry in raw.get("hosts") or []:
        h = FakeHost(
            ip=str(entry["ip"]),
            hostname=str(entry["hostname"]),
            os=str(entry.get("os", "linux")),
            icmp=bool(entry.get("icmp", False)),
            pivot=bool(entry.get("pivot", False)),
            ctid=int(entry["ctid"]) if entry.get("ctid") is not None else None,
            ssh_deny=str(entry.get("ssh", "")) == "deny",
            default_state=str(entry.get("default", "closed")),
            ports=list(entry.get("ports") or []),
            http=dict(entry.get("http") or {}),
        )
        hosts[h.ip] = h
    return Topology(domain=str(raw.get("domain", "corp.local")),
                     subnets=list(raw.get("subnets") or []), hosts=hosts)


def _same_vlan(session: Session, ip: str) -> bool:
    try:
        mine = ipaddress.ip_network(f"{session.host.ip}/24", strict=False)
        return ipaddress.ip_address(ip) in mine
    except ValueError:
        return False


def _reachable(session: Session, target: FakeHost) -> bool:
    """A honeypot only shows hosts on its own VLAN as directly reachable;
    other VLANs appear filtered/down until policy D01 exposes that specific
    host or D07 reveals its whole segment."""
    if _same_vlan(session, target.ip):
        return True
    if target.hostname in (session.exposed_hosts or []):
        return True
    revealed = {s.get("subnet") for s in (session.revealed_segments or [])}
    topo = load_topology()
    sub = topo.subnet_of(target.ip)
    return bool(sub and sub.get("cidr") in revealed)


def self_as_fakehost(session: Session) -> FakeHost:
    """This honeypot's own entry (or a synthesised one) for `nmap 127.0.0.1`."""
    topo = load_topology()
    existing = topo.hosts.get(session.host.ip)
    if existing:
        return existing
    ports = [{"port": 22, "service": "ssh",
              "version": "OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)"}]
    for svc in session.host.services:
        p = svc.get("port")
        if p and p != 22:
            ports.append({"port": p, "service": svc.get("name", "unknown"), "version": ""})
    return FakeHost(ip=session.host.ip, hostname=session.host.hostname, ports=ports)


# --------------------------------------------------------------------------- nmap


_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_PORT_FLAG_RE = re.compile(r"-p\s*\S+")


def _parse_nmap_args(args: list[str]) -> dict[str, Any]:
    joined = " ".join(args)
    opts = {
        "version": "-sV" in args or "-A" in args,
        "os": "-O" in args or "-A" in args,
        "scripts": "-sC" in args or "-A" in args,
        "no_ping": "-Pn" in args,
        "udp": "-sU" in args,
        "all_ports": "-p-" in args,
        "ports": None,
        "targets": [],
    }
    m = re.search(r"-p\s*([\d,\-]+)", joined)
    if m and "-p-" not in args:
        wanted: set[int] = set()
        for part in m.group(1).split(","):
            if "-" in part:
                a, b = part.split("-")
                wanted.update(range(int(a), int(b) + 1))
            elif part.isdigit():
                wanted.add(int(part))
        opts["ports"] = wanted
    skip_next = False
    for i, a in enumerate(args):
        if skip_next:
            skip_next = False
            continue
        if a.startswith("-"):
            if a in {"-p", "-oA", "-oN", "-oX", "-oG", "--top-ports", "-T", "-e"}:
                skip_next = True
            continue
        opts["targets"].append(a)
    return opts


def _expand_targets(tokens: list[str]) -> list[str]:
    out: list[str] = []
    for tok in tokens:
        if "/" in tok and _IP_RE.match(tok.split("/")[0]):
            try:
                net = ipaddress.ip_network(tok, strict=False)
                if net.num_addresses <= 256:
                    out.extend(str(h) for h in net.hosts())
                else:
                    out.append(tok)
            except ValueError:
                out.append(tok)
        elif re.match(r"^\d{1,3}(?:\.\d{1,3}){2}\.\d{1,3}-\d{1,3}$", tok):
            base, last = tok.rsplit(".", 1)
            lo, hi = last.split("-")
            out.extend(f"{base}.{i}" for i in range(int(lo), int(hi) + 1))
        else:
            out.append(tok)
    return out


def _host_timing(target: str) -> tuple[float, float]:
    h = int(hashlib.sha256(target.encode()).hexdigest()[:6], 16)
    latency = 0.00030 + (h % 500) / 1_000_000
    scan_secs = 1.2 + (h % 400) / 100
    return round(latency, 5), round(scan_secs, 2)


def _report_one(session: Session, topo: Topology, target: str, opts: dict[str, Any]) -> str:
    resolved = topo.find(target) if not _IP_RE.match(target) else topo.hosts.get(target)
    ip = resolved.ip if resolved else target
    lines = [f"Nmap scan report for {resolved.fqdn} ({ip})" if resolved and resolved.hostname else
             f"Nmap scan report for {ip}"]
    latency, scan_secs = _host_timing(ip)

    if resolved is None or (not _same_vlan(session, ip) and not _reachable(session, resolved)):
        if opts["no_ping"]:
            lines.append(f"Host is up (unknown latency).")
            lines.append("All 1000 scanned ports on this host are filtered")
        else:
            lines.append("Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn")
            return "\n".join(lines) + "\n"
        return "\n".join(lines) + f"\nNmap done: 1 IP address (1 host up) scanned in {scan_secs} seconds\n"

    lines.append(f"Host is up ({latency}s latency).")
    if resolved.ip != session.host.ip:
        lines.append(f"rDNS record for {ip}: {resolved.fqdn}")

    ports = resolved.ports
    if opts["ports"] is not None:
        ports = [p for p in ports if p["port"] in opts["ports"]]
    closed_n = (65535 if opts["all_ports"] else 1000) - len(ports)
    state_word = resolved.default_state if resolved.default_state != "closed" else "closed"

    if not ports:
        lines.append(f"All {65535 if opts['all_ports'] else 1000} scanned ports on this host are {state_word}")
    else:
        lines.append(f"Not shown: {closed_n} {state_word} ports")
        lines.append("PORT     STATE SERVICE" + ("     VERSION" if opts["version"] else ""))
        for p in sorted(ports, key=lambda x: x["port"]):
            port_s = f"{p['port']}/tcp"
            service = p.get("service", "unknown")
            row = f"{port_s:<8} open  {service:<10}"
            if opts["version"]:
                row += f" {p.get('version', '')}"
            lines.append(row.rstrip())
        if opts["scripts"] and resolved.http:
            lines.append("| http-title: " + str(resolved.http.get("title", "")))
            lines.append("|_http-server-header: " + str(resolved.http.get("server", "")))

    if opts["os"]:
        guess = {"windows": "Microsoft Windows Server 2019 or 2022", "linux": "Linux 5.15 - 6.1",
                 "freebsd": "FreeBSD 13.2-RELEASE"}.get(resolved.os, "Linux 5.15 - 6.1")
        lines.append(f"Device type: {'general purpose' if resolved.os != 'freebsd' else 'firewall'}")
        lines.append(f"Running: {guess}")
        lines.append(f"OS details: {guess}")
        lines.append(f"Network Distance: {1 if _same_vlan(session, ip) else 2} hops")

    if opts["version"] or opts["scripts"]:
        lines.append("Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .")
    return "\n".join(lines) + f"\nNmap done: 1 IP address (1 host up) scanned in {scan_secs} seconds\n"


def nmap(session: Session, args: list[str]) -> tuple[str, str, int]:
    opts = _parse_nmap_args(args)
    topo = load_topology()
    raw_targets = opts["targets"] or ["127.0.0.1"]
    targets = _expand_targets(raw_targets)
    if len(targets) > 1:
        # Ping-sweep style summary across a /24 or small range.
        up = []
        for t in targets:
            resolved = topo.hosts.get(t)
            if resolved and (_same_vlan(session, t) or _reachable(session, resolved)):
                up.append(t)
            elif t == session.host.ip:
                up.append(t)
        header = (f"Starting Nmap {NMAP_VERSION} ( https://nmap.org ) at "
                  f"{clock.now().strftime('%Y-%m-%d %H:%M %Z')}\n")
        if "-sn" in args or "-sP" in args:
            body = "".join(
                f"Nmap scan report for {topo.hosts[t].fqdn} ({t})\nHost is up ({_host_timing(t)[0]}s latency).\n"
                for t in up
            )
            return (header + body +
                    f"Nmap done: {len(targets)} IP addresses ({len(up)} hosts up) scanned in "
                    f"{round(len(targets) * 0.08, 2)} seconds\n"), "", 0
        body = "\n".join(_report_one(session, topo, t, opts) for t in up)
        return (header + body +
                f"\nNmap done: {len(targets)} IP addresses ({len(up)} hosts up) scanned in "
                f"{round(len(targets) * 0.08 + 1, 2)} seconds\n"), "", 0

    target = targets[0]
    if target in {"127.0.0.1", "localhost", session.host.ip}:
        fh = self_as_fakehost(session)
        topo.hosts.setdefault(fh.ip, fh)
        target = fh.ip
    header = (f"Starting Nmap {NMAP_VERSION} ( https://nmap.org ) at "
              f"{clock.now().strftime('%Y-%m-%d %H:%M %Z')}\n")
    return header + _report_one(session, topo, target, opts), "", 0


# --------------------------------------------------------------------------- ping


def ping(session: Session, args: list[str]) -> tuple[str, str, int]:
    targets = [a for a in args if not a.startswith("-")]
    if not targets:
        return "", "ping: usage error: Destination address required\n", 2
    target = targets[-1]
    count = 4
    m = re.search(r"-c\s*(\d+)", " ".join(args))
    if m:
        count = int(m.group(1))
    count = min(count, 10)

    topo = load_topology()
    resolved = topo.find(target) if not _IP_RE.match(target) else topo.hosts.get(target)
    ip = resolved.ip if resolved else (target if _IP_RE.match(target) else None)

    if ip is None:
        return "", f"ping: {target}: Name or service not known\n", 2

    up = ip == session.host.ip or (resolved and (resolved.icmp or _same_vlan(session, ip)) and _reachable(session, resolved))
    if not up:
        lines = [f"PING {target} ({ip}) 56(84) bytes of data."]
        lines.append(f"\n--- {target} ping statistics ---")
        lines.append(f"{count} packets transmitted, 0 received, 100% packet loss, time {count * 1000 + 23}ms")
        return "\n".join(lines) + "\n", "", 1

    latency, _ = _host_timing(ip)
    base_ms = latency * 1000 + 0.1
    lines = [f"PING {target} ({ip}) 56(84) bytes of data."]
    for i in range(count):
        jitter = (int(hashlib.sha256(f"{ip}{i}".encode()).hexdigest()[:4], 16) % 40) / 100
        lines.append(f"64 bytes from {ip}: icmp_seq={i + 1} ttl=64 time={base_ms + jitter:.2f} ms")
    lines.append(f"\n--- {target} ping statistics ---")
    lines.append(f"{count} packets transmitted, {count} received, 0% packet loss, time {count * 1000 + 50}ms")
    lines.append(f"rtt min/avg/max/mdev = {base_ms:.2f}/{base_ms + 0.15:.2f}/{base_ms + 0.35:.2f}/0.08 ms")
    return "\n".join(lines) + "\n", "", 0


# --------------------------------------------------------------------------- nc / telnet / curl (port probe)


def _port_state(session: Session, topo: Topology, ip: str, port: int) -> tuple[bool, FakeHost | None]:
    resolved = topo.hosts.get(ip) if _IP_RE.match(ip) else topo.find(ip)
    real_ip = resolved.ip if resolved else ip
    if real_ip == session.host.ip:
        is_open = port == 22 or port in {s.get("port") for s in session.host.services}
        return is_open, resolved
    if resolved is None:
        return False, None
    if not _reachable(session, resolved):
        return False, resolved
    is_open = any(p["port"] == port for p in resolved.ports)
    return is_open, resolved


def nc_probe(session: Session, args: list[str]) -> tuple[str, str, int]:
    plain = [a for a in args if not a.startswith("-")]
    scan = "-z" in args or "-zv" in args
    if len(plain) < 2:
        return "", "nc: usage error\n", 1
    target, port_s = plain[0], plain[-1]
    try:
        port = int(port_s)
    except ValueError:
        return "", f"nc: port number invalid: {port_s}\n", 1
    topo = load_topology()
    is_open, resolved = _port_state(session, topo, target, port)
    label = f"{target} [{resolved.ip if resolved else target}] {port}"
    if is_open:
        line = f"Connection to {target} {port} port [tcp/*] succeeded!"
        if scan:
            return line + "\n", "", 0
        service = next((p.get("service") for p in (resolved.ports if resolved else []) if p["port"] == port), "")
        banner = ""
        if service == "ssh":
            banner = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10\n"
        return banner, line + "\n", 0
    return "", f"nc: connect to {target} port {port} (tcp) failed: Connection refused\n", 1


def telnet(session: Session, args: list[str]) -> tuple[str, str, int]:
    plain = [a for a in args if not a.startswith("-")]
    if not plain:
        return "", "", 0
    target = plain[0]
    port = int(plain[1]) if len(plain) > 1 and plain[1].isdigit() else 23
    topo = load_topology()
    is_open, resolved = _port_state(session, topo, target, port)
    if not is_open:
        return "", f"Trying {target}...\ntelnet: Unable to connect to remote host: Connection refused\n", 1
    service = next((p.get("service") for p in (resolved.ports if resolved else []) if p["port"] == port), "")
    if service == "ssh":
        return f"Trying {target}...\nConnected to {target}.\nEscape character is '^]'.\nSSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10\n", "", 0
    return f"Trying {target}...\nConnected to {target}.\nEscape character is '^]'.\n", "", 0


def curl_remote(session: Session, args: list[str], target_host: str) -> tuple[str, str, int]:
    """curl to another fake host's http(s) port (lab-internal only, not external)."""
    head_only = "-I" in args or "--head" in args
    topo = load_topology()
    m = re.search(r"https?://([^/:\s]+)(?::(\d+))?", target_host)
    host_part = m.group(1) if m else target_host
    port = int(m.group(2)) if m and m.group(2) else (443 if target_host.startswith("https") else 80)
    resolved = topo.find(host_part) if not _IP_RE.match(host_part) else topo.hosts.get(host_part)
    is_open, resolved = _port_state(session, topo, resolved.ip if resolved else host_part, port)
    if not is_open or not resolved or not resolved.http:
        return "", f"curl: (7) Failed to connect to {host_part} port {port}: Connection refused\n", 7
    server = resolved.http.get("server", "nginx")
    title = resolved.http.get("title", "")
    if head_only:
        return (f"HTTP/1.1 200 OK\r\nServer: {server}\r\nContent-Type: text/html\r\n"
                f"Content-Length: {120 + len(title)}\r\nConnection: keep-alive\r\n\r\n"), "", 0
    return f"<html><head><title>{title}</title></head><body><h1>{title}</h1></body></html>\n", "", 0


# --------------------------------------------------------------------------- dns / arp


def dig(session: Session, args: list[str]) -> tuple[str, str, int]:
    names = [a for a in args if not a.startswith("-") and not a.startswith("@")]
    if not names:
        return "", "", 0
    name = names[0]
    topo = load_topology()
    resolved = topo.find(name)
    header = (f"; <<>> DiG 9.18.30-0ubuntu0.22.04.1-Ubuntu <<>> {name}\n"
              ";; global options: +cmd\n")
    if not resolved:
        return header + ";; connection timed out; no servers could be reached\n", "", 9
    body = (
        ";; Got answer:\n;; ANSWER SECTION:\n"
        f"{resolved.fqdn}.\t\t300\tIN\tA\t{resolved.ip}\n\n"
        f";; Query time: {2 + hash(name) % 20} msec\n;; SERVER: 127.0.0.53#53(127.0.0.53)\n"
    )
    return header + body, "", 0


def nslookup_or_host(session: Session, prog: str, args: list[str]) -> tuple[str, str, int]:
    names = [a for a in args if not a.startswith("-")]
    if not names:
        return "", "", 0
    name = names[0]
    topo = load_topology()
    resolved = topo.find(name)
    if not resolved:
        if prog == "host":
            return f"Host {name} not found: 3(NXDOMAIN)\n", "", 1
        return f"Server:\t\t127.0.0.53\nAddress:\t127.0.0.53#53\n\n** server can't find {name}: NXDOMAIN\n", "", 1
    if prog == "host":
        return f"{resolved.fqdn} has address {resolved.ip}\n", "", 0
    return (f"Server:\t\t127.0.0.53\nAddress:\t127.0.0.53#53\n\n"
            f"Name:\t{resolved.fqdn}\nAddress: {resolved.ip}\n"), "", 0


def arp_table(session: Session) -> tuple[str, str, int]:
    topo = load_topology()
    rows = ["Address                  HWtype  HWaddress           Flags Mask            Iface"]
    for h in topo.hosts.values():
        if not _same_vlan(session, h.ip) or h.ip == session.host.ip:
            continue
        mac = ":".join(hashlib.sha256(h.ip.encode()).hexdigest()[i:i + 2] for i in (0, 2, 4, 6, 8, 10))
        rows.append(f"{h.ip:<25} ether   {mac}   C                     eth0")
    return "\n".join(rows) + "\n", "", 0


# --------------------------------------------------------------------------- ssh pivot decision


@dataclass
class SshTarget:
    ip: str
    hostname: str
    reachable: bool
    is_pivot: bool
    accepts_creds: bool
    ctid: int | None = None


def resolve_ssh_target(session: Session, destination: str) -> SshTarget | None:
    """Decide what `ssh user@destination` should do — not perform it.

    is_pivot=True means the front-door should relay to the real sensor on
    that honeypot's :2222; otherwise the caller plays theater locally
    (deny password, or 'no route to host' if unreachable).
    """
    host_part = destination.split("@")[-1]
    topo = load_topology()
    resolved = topo.find(host_part) if not _IP_RE.match(host_part) else topo.hosts.get(host_part)
    if resolved is None:
        return None
    reachable = resolved.ip == session.host.ip or _reachable(session, resolved)
    return SshTarget(
        ip=resolved.ip,
        hostname=resolved.hostname,
        reachable=reachable,
        is_pivot=reachable and resolved.pivot,
        accepts_creds=reachable and not resolved.ssh_deny,
        ctid=resolved.ctid,
    )
