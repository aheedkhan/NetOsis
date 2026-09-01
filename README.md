# CyberSnare local lab

A full simulated organisation — **NexusCorp Industrial Systems** — running entirely
in containers on one machine: a perimeter firewall, a DMZ with real TLS-terminated
services, a corporate LAN, a protected datacenter, and a deception zone behind
both firewalls. An adaptive control plane (sensor → decision → deception →
intelligence) escalates or blocks each address that reaches the perimeter based
on **what it does**, not what it claims to be.

Everything below `internet` (203.0.113.0/24, a simulated address block — TEST-NET-3)
is only reachable through nftables rules on `cs-edge-fw` and `cs-core-fw`; there is
no other path between zones. Nothing in this repo reaches the real Internet, and
every port this stack publishes to the host is bound to `127.0.0.1` — if you
change a `ports:` entry to `0.0.0.0`, you have left the local-lab contract.

## Host requirements (Fedora + Podman)

**Only Podman is required on the host.** Python, Zeek, nftables, curl, and the SSH
client all run inside containers.

```bash
sudo dnf install -y podman    # one-time on a fresh Fedora box
```

Optional: `make` (Fedora Workstation includes it). If you prefer not to use make, use `./cs` instead.

## Quick start

```bash
chmod +x cs scripts/*.sh
./cs bootstrap    # enable podman user socket, sanity-check compose
./cs up           # build the images, start the full org topology (21 containers;
                   # +2 with ./cs attacker or ./cs operator)
./cs verify       # health, surfaces, isolation, Zeek/HASSH/JA4 telemetry
```

Equivalent with make:

```bash
make bootstrap && make up && make verify
```

## See it discriminate: bot vs. human

The two commands below run identical network paths from the same "Internet"
segment — through the perimeter firewall, DNAT'd to the same published address —
with the only difference being *behaviour*. `lib/cs/operator.py` classifies each
one from timing, tool fingerprints, and command patterns; the decision plane acts
on the verdict.

```bash
./cs attacker     # fast port sweep + credential spray → classified `automated`,
                   # dropped at cs-edge-fw within seconds. ./cs blocked to see it.

./cs operator     # a hand-paced session (think-time, a typo then its correction,
                   # orientation before action) → classified `interactive_operator`,
                   # escalated into a real restricted shell.
```

`./cs monitor` shows both in real time; the SIEM dashboard is at
`http://127.0.0.1:18090/`.

## Topology

```
                    internet  203.0.113.0/24  (simulated — attacker/operator live here)
                        │
                  cs-edge-fw   nftables: DNAT, perimeter scan telemetry, blocklist
                   ┌────┴────┐
                  dmz       transit
             172.31.10.0/24   172.31.99.0/24
          www01 mail01 vpn01       │
             (real, TLS)     cs-core-fw   nftables: segmentation, containment
                               ┌────┼────────────┐
                             corp          datacenter      deception
                       10.10.20.0/24    10.10.30.0/24    10.200.2.0/24
                   dc01 fs01 erp01     db01 bkp01        sensor (ssh :2222,
                   wks01 (benign)    NEVER reachable      https :8443) —
                                      from deception       Zeek/HASSH/JA4
                                                              │
                                                          egress 10.200.3.0/24
                                                          sinkhole, sandbox
                                                          (off both firewalls)

mgmt 10.200.1.0/24 (internal)  logger · decision · gnn-scorer · intelligence · zeek-ingest
```

Zeek, SSH, and HTTP/HTTPS share one network namespace on `cs-sensor` (a lab tap).
Podman bridges cannot sniff unicast between two other containers, so this is how
Zeek sees KEX and TLS ClientHello without a second addressable monitor on the
deception LAN. The capture filter excludes the management subnet's own polling
and ARP/IPv6 noise — see the comment in `sensor/zeek/entrypoint.sh` for why that
exclusion has to be surgical rather than a blanket subnet drop.

The published address block, as an outside actor discovers it:

| Address | Name | Routes to |
|---|---|---|
| `203.0.113.10` | www.nexuscorp.example | `www01` — real marketing site (TLS) |
| `203.0.113.11` | mail.nexuscorp.example | `mail01` — webmail portal (TLS) |
| `203.0.113.12` | vpn.nexuscorp.example | `vpn01` — SSL-VPN portal (TLS) |
| `203.0.113.20` | dev.nexuscorp.example | `cs-sensor` — **the deception surface**, ports 22/443 |

`config/topology.json` records the zone/host/firewall-policy map that the compose
topology and the firewall rulesets implement. It is intended as the shared source
the dashboard and PDF figures read from rather than hardcoding the map a second
time — that wiring is not done yet; today it is documentation and a build-time
reference, not something the running services consume.

## Why not Cowrie?

| | Cowrie / T-Pot | CyberSnare |
|---|----------------|------------|
| Architecture | Static honeypot server | **Control plane** + interchangeable actuators |
| Escalation | Fixed config | **Dynamic manifests** (L1→L2→L3) per actor behaviour |
| Identity | Mostly IP | **HASSH + JA4** actor linkage across IPs |
| Decision | None | **Belief state + intent** (P0/P1/P2 policies) |
| Egress | Often blocked or ignored | **Instrumented sinkhole** (stage 0) with telemetry |
| Monitoring | Log files | **Live activity monitor** + JSONL + Zeek |

```bash
./cs up-adaptive          # Arm B — auto-escalates as actors engage
./cs monitor              # live actors, transitions, events
```

## Commands

| Command | What it does |
|---|---|
| `./cs up` | Build images and start the full org topology |
| `./cs down` | Stop and remove containers |
| `./cs verify` | Health, surfaces, isolation, Zeek/HASSH/JA4 telemetry |
| `./cs gate` | The §4.5 nineteen-property authentication gate |
| `./cs milestone` | Full milestone-1 verification (lab + P4/P5 artefacts) |
| `./cs attacker` | Automated profile from outside — expect a firewall block |
| `./cs operator` | Hand-paced profile from outside — expect an engaged shell |
| `./cs attacker-shell` / `./cs operator-shell` | SSH into either container manually |
| `./cs blocked` | Addresses currently dropped at each firewall |
| `./cs observe` | Bring the lab up with the operator gate OFF, for corpus collection |
| `./cs train-gnn` | Train the actor graph model on `data/events/events.jsonl` |
| `./cs monitor` | Live actor/transition activity |
| `./cs health` / `./cs events` | Logger + decision `/health`; last 20 JSONL events |
| `./cs up-adaptive` / `./cs up-p2` | Arm B (P1 + GNN) / Arm C (P2 intent-conditioned) |
| `./cs export` / `./cs import` | Save/load images via `dist/` for offline transfer |

Raw log: `data/events/events.jsonl`. Zeek JSON: `data/zeek/`.

### Training the graph model

The GNN ships **untrained** — `score_graph()` refuses to use random weights and
returns explicit priors instead (see `lib/cs/gnn_model.py`). To get a real model:

```bash
./cs observe            # gate OFF, so a blocked bot doesn't cut the corpus short
./cs attacker && ./cs operator      # or: real traffic over a few days
./cs train-gnn           # trains on cs.patterns weak labels, saves data/models/actor-gnn.pt
podman restart cs-gnn    # load the new checkpoint
./cs up                  # back to the gate-on, GNN-blended production mode
```

Targets come from `lib/cs/patterns.py` — auditable, ATT&CK/Engage-mapped sequence
rules — rather than any hand-labelled corpus, since none exists for a honeypot
that has not been deployed yet. See the module docstring for why that is an
honest design rather than a shortcut.

## Production deployment (2× Ubuntu + k3s)

This repo's `./cs up` topology is the full simulation on **one machine** — every
zone is a container, every firewall is a container. `deploy/org/` is a different,
not-yet-built thing: a production-shaped layout across **two real servers**
(`cs-edge` with a real public site and firewall, `cs-lab` running k3s), connected
by WireGuard. See `deploy/org/TOPOLOGY.md` and `deploy/k8s/README.md` — that
scaffolding is unstarted (`deploy/k8s/` is manifests only, nothing has been run
against a cluster).

| Arm | `CS_POLICY` | What decides escalation |
|-----|-------------|-------------------------|
| A | P0 | Static manifest (control) |
| B | P1 | GNN scores + utility function |
| C | P2 | GNN intent distribution → manifest |

## Portable to another Fedora machine

1. **With internet** — clone or copy the repo, then:

   ```bash
   cd cybersnare
   ./cs bootstrap && ./cs up && ./cs verify
   ```

2. **Offline / slow link** — on the build machine:

   ```bash
   ./cs up && ./cs export
   ```

   Copy the whole project directory (including `dist/*.tar`) to the target host, then:

   ```bash
   ./cs import && ./cs up && ./cs verify
   ```

SELinux volume labels (`:z`) are set in `compose.yml` for Fedora rootless Podman.

## Containers

| Container | Plane | Job |
|---|---|---|
| `cs-edge-fw` | Perimeter | nftables: DNAT to published services, perimeter scan telemetry, blocklist |
| `cs-core-fw` | Segmentation | nftables: zone isolation, containment invariant, east-west telemetry |
| `www01` / `mail01` / `vpn01` | DMZ | Real nginx + TLS — the organisation's actual public services |
| `dc01` / `fs01` / `erp01` / `wks01` | Corp LAN | Decoy content + one benign traffic generator |
| `db01` / `bkp01` | Datacenter | Never reachable from the deception zone — the containment invariant |
| `cs-logger` | Intelligence / bus | Append-only JSONL; forwards to decision |
| `cs-decision` | Decision | Policy P0/P1/P2, belief state, operator gate, manifest reconciliation |
| `cs-gnn` | Decision | Graph model over the actor graph — priors until trained |
| `cs-sensor` | Sensor | Zeek on the shared deception netns (HASSH, JA4) |
| `cs-zeek-ingest` | Sensor | Tails Zeek JSON into the canonical envelope |
| `cs-ssh` | Deception | asyncssh KEX; auth per the current manifest |
| `cs-http` | Deception | HTTPS-only, login 401 unless escalated |
| `cs-sinkhole` | Egress | Stage-0 DNS + HTTP, off both firewalls |
| `cs-sandbox` | Egress | Unprivileged, no mgmt or Internet route |
| `cs-intelligence` | Intelligence | SIEM dashboard + milestone report API, `:18090` |
| `cs-attacker` / `cs-operator` | Overlay (`compose.attacker.yml`) | Automated / hand-paced demo actors, outside the perimeter |

Images: `localhost/cybersnare-python:lab`, `localhost/cybersnare-zeek:lab`,
`localhost/cybersnare-gnn:lab`, `localhost/cybersnare-firewall:lab`,
`localhost/cybersnare-attacker:lab`, `localhost/cybersnare-verify:lab`.

## Roadmap items still gated

See **`docs/SCOPE-STATUS.md`** for design-record alignment (in scope / deferred / post-milestone).

L2 shell requires passing `./cs gate` (§4.5) and supervisor approval file. Commands:

```bash
./cs gate                  # nineteen-property authentication gate
./cs set-level L2          # pin L2 manifest (auth open)
./cs verify-l2             # SSH + HTTPS engage smoke test
./cs up-adaptive           # Arm B — P1 + GNN
./cs up-p2                 # Arm C — P2 intent-conditioned
```

Still gated for milestone 1: L3 immerse actuators (P6), Suricata (deferrable), the
two-server production deploy with a live WireGuard edge, and a local LLM host.
The P4 intelligence dashboard and P5 evaluation scripts are built and running —
see `docs/SCOPE-STATUS.md` for the current, authoritative status of every item.

Event schema: `config/event-schema.json`.

## Safety

- Networks are `internal: true`.
- Sandbox drops all capabilities.
- Sinkhole never originates outbound connections.
- If you change `ports:` to `0.0.0.0`, you have left the local-lab contract.
