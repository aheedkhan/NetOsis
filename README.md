# CyberSnare local lab (Scope B)

Local-only adaptive-deception lab. Scope B **extends** Scope A: same four planes, same JSONL log, same closed login. The new piece is the **sensor plane** (Zeek) plus a real SSH handshake and HTTPS so HASSH/JA4 exist on the wire.

Nothing listens on `0.0.0.0`. Published ports are bound to `127.0.0.1` only. Authentication is **closed**. Do not port-forward this stack off the machine.

## Topology

Zeek, SSH, and HTTP/HTTPS share one network namespace (a lab tap). Podman bridges cannot sniff unicast between two other containers, so this is how Zeek sees KEX and TLS ClientHello without a second addressable monitor on the deception LAN.

```
host loopback
  127.0.0.1:2222  →  ssh (KEX, auth refused)
  127.0.0.1:8080  →  http portal
  127.0.0.1:8443  →  https portal
  127.0.0.1:18088 →  logger        (mgmt 10.200.1.10)
  127.0.0.1:19000 →  decision      (mgmt 10.200.1.11)

cs-mgmt      10.200.1.0/24   internal  logger, decision, zeek-ingest, sensor-mgmt
cs-deception 10.200.2.0/24   internal  sensor 10.200.2.10 (ssh/http share this netns)
cs-egress    10.200.3.0/24   internal  sinkhole 10.200.3.2, sandbox 10.200.3.10
```

## Start

```bash
make up
make verify
```

`make up` starts the user API socket first (`systemctl --user start podman.socket`).

```bash
make health
make events
make logs
make down
```

Raw log: `data/events/events.jsonl`. Zeek JSON: `data/zeek/`.

## Containers

| Container | Plane | Job |
|---|---|---|
| `cs-logger` | Intelligence / bus | Append-only JSONL; forwards to decision |
| `cs-decision` | Decision | Policy P0 plus actor map (`hassh:` / `ja4:` / `ip:`) |
| `cs-sensor` | Sensor | Zeek on the shared deception netns (HASSH, JA4) |
| `cs-zeek-ingest` | Sensor | Tails Zeek JSON into the frozen envelope |
| `cs-ssh` | Deception | asyncssh KEX, every login refused |
| `cs-http` | Deception | HTTP :8080 and HTTPS :8443, login 401 |
| `cs-sinkhole` | Egress | Stage-0 DNS + HTTP |
| `cs-sandbox` | Attacker stand-in | Unprivileged, no mgmt or internet route |

## Still not in this slice

Suricata, SSH login into a shell, Kubernetes, WireGuard, public IPs, hosted LLMs, policies P1/P2. Opening authentication still requires the nineteen-property gate.

Event schema: `config/event-schema.json`.

## Safety

- Networks are `internal: true`.
- Sandbox drops all capabilities.
- Sinkhole never originates outbound connections.
- If you change `ports:` to `0.0.0.0`, you have left the local-lab contract.
