# CyberSnare local lab (Scope A)

Local-only adaptive-deception **skeleton**. It is not the full Milestone 1 system.

This slice exists to prove four things before any public exposure or SSH login:

1. The four planes exist as separate processes.
2. A canonical event envelope is frozen and the JSONL log is the system of record.
3. Policy P0 is a stub that always emits the same manifest (auth closed, no shell).
4. A disposable sandbox has **no path to the internet or the management network**; outbound DNS/HTTP are sinkholed.

Nothing listens on `0.0.0.0`. Published ports are bound to `127.0.0.1` only. Authentication is **closed**. Do not port-forward this stack off the machine.

## Topology

```
host loopback
  127.0.0.1:2222  →  ssh-surface   (deception 10.200.2.10)
  127.0.0.1:8080  →  http-surface  (deception 10.200.2.11)
  127.0.0.1:18088 →  logger        (mgmt 10.200.1.10)
  127.0.0.1:19000 →  decision      (mgmt 10.200.1.11)

cs-mgmt      10.200.1.0/24   internal  logger, decision
cs-deception 10.200.2.0/24   internal  ssh, http
cs-egress    10.200.3.0/24   internal  sinkhole 10.200.3.2, sandbox 10.200.3.10
```

The sandbox is attached **only** to `cs-egress`. Podman would otherwise point DNS at the bridge (`.1`), so `config/resolv.sandbox` is bind-mounted as `/etc/resolv.conf` and forces `10.200.3.2`. Stage 0 means a lookup for `malware.example` returns `10.200.3.2` and `wget http://malware.example/x.sh` appears to succeed without leaving the lab.

## Start

Needs Podman 5+ with Compose. `make up` starts the user API socket first (`systemctl --user start podman.socket`).

```bash
make up
make verify
```

Useful:

```bash
make health          # logger + decision
make events          # last events in the JSONL
make logs
make down
```

Raw log on disk: `data/events/events.jsonl`.

## What each container is

| Container | Plane | Job in this slice |
|---|---|---|
| `cs-logger` | Intelligence / bus | Accepts events, appends JSONL, forwards to decision. Disk-fill rotate at 100 MiB. |
| `cs-decision` | Decision | Policy **P0**: record belief, always the same manifest. |
| `cs-ssh` | Deception | RFC 4253 identification string, then close. No KEX, no auth. |
| `cs-http` | Deception | Fake NexusCorp portal. Login always 401. |
| `cs-sinkhole` | Sensor / egress | Stage-0 DNS + HTTP responder. |
| `cs-sandbox` | Attacker workload stand-in | Unprivileged, read-only, 64 MiB, no mgmt route. |

## Not in this slice (by design)

Zeek, Suricata, real SSH authentication, a disposable shell, Kubernetes, WireGuard, public IPs, hosted LLMs, policies P1/P2, ATT&CK dashboards. Those belong in later phases. Opening SSH authentication requires the nineteen-property gate in the design record — this lab is how you start demonstrating the isolation properties, not a waiver of that gate.

Event schema: `config/event-schema.json`. Identity is `ip:<address>` until Zeek HASSH/JA4 exist.

## Safety

- Networks are `internal: true` (no NAT to the real internet).
- Sandbox drops all capabilities and cannot get new privileges.
- Sinkhole never originates outbound connections.
- If you change `ports:` to `0.0.0.0`, you have left the local-lab contract. Do not do that.
