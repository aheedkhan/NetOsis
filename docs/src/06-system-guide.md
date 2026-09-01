# 1. What CyberSnare is

CyberSnare is a simulated organisation — **NexusCorp Industrial Systems** — with an
adaptive deception control plane running underneath it. It is not a single
honeypot: it is a perimeter firewall, a DMZ of real services, a corporate LAN,
a protected datacenter, and a deception zone published behind the same
firewall as everything else, all watched by four cooperating planes (sensor,
decision, deception, intelligence) that decide — per adversary, in real time —
whether to drop, observe, or engage.

The core research claim is narrow and testable: **an adversary's capability can
be inferred from behaviour alone** (timing, tool fingerprints, command
patterns) **and that inference should gate how much deception is spent on
them.** An automated scanner is dropped at the firewall within seconds, because
there is nothing further to learn from it. A human operator is escalated into
a real restricted shell, because that is the traffic the whole system exists
to study.

Two independent deployment targets implement the same design from the same
source of truth (`config/topology.json`):

- **Podman compose** — every zone and firewall is a container, on one machine.
- **Kubernetes (kind + Cilium)** — every zone is a namespace, segmentation is
  `CiliumNetworkPolicy` enforced in the kernel by an eBPF dataplane.

Both are built and verified as of this document. What follows describes the
system as it actually runs, not as it was originally planned — three prior
design iterations were discarded along the way (see `docs/CyberSnare-Phase0-
Design-Record.pdf` for that history if it matters to you); this document is
the as-built reference.

---

# 2. Architecture

## 2.1 The four planes

```
   SENSOR              DECISION             DECEPTION           INTELLIGENCE
 -----------         -------------        -------------        --------------
 Zeek (HASSH,        Belief state per     Manifests: L0-L3,     JSONL system
 JA4), firewall      actor. Operator      BURN, BLOCK.          of record.
 accept/deny          classifier          Actuators             SIEM dashboard,
 counters, app         (bot vs             (ssh/http/           ATT&CK/Engage
 telemetry.             human).            sinkhole) reconcile   mapping,
                       Policy P0/P1/P2.     reality toward it.    per-actor
        |                    |                    |              timelines.
        +--------------------+--------------------+------------------+
                          one append-only JSONL event log
                     canonical envelope: config/event-schema.json
```

Every event — a firewall drop, an SSH auth attempt, a shell command, a
sinkhole hit, a policy transition — is written once to this log in one
schema. Nothing downstream re-derives ground truth from a different source;
the dashboard, the milestone report, and the analysis scripts all read the
same JSONL file the decision plane also reads.

## 2.2 The organisation (compose deployment)

```
                    internet  203.0.113.0/24  (simulated — TEST-NET-3)
                        |
                  cs-edge-fw   nftables: DNAT, perimeter scan telemetry,
                   +----+----+            blocklist (decision-plane actuated)
                  dmz       transit
             172.31.10.0/24   172.31.99.0/24
          www01 mail01 vpn01       |
             (real, TLS)     cs-core-fw   nftables: segmentation, containment
                               +----+------------+
                             corp          datacenter      deception
                       10.10.20.0/24    10.10.30.0/24    10.200.2.0/24
                   dc01 fs01 erp01     db01 bkp01        sensor (Zeek + ssh
                   wks01 (benign)     NEVER reachable     :2222 + https :8443)
                                       from deception          |
                                                            egress 10.200.3.0/24
                                                          sinkhole, sandbox
                                                          (off both firewalls)

mgmt 10.200.1.0/24 (internal)  logger · decision · gnn-scorer · intelligence · zeek-ingest
```

The two firewall containers are the **only** containers attached to more than
one zone bridge. There is no other path between zones — an nftables rule
either exists or the packet does not arrive. `deploy/org/firewall/edge.nft`
and `core.nft` are the actual rulesets; the diagram above is what they
implement, not a separate claim about it.

**The containment invariant**, enforced structurally rather than merely
logged: the deception zone has no forward rule to the datacenter and no
forward rule to the internet. An adversary who fully compromises the honeypot
still cannot reach real data, and cannot originate outbound traffic except
through the sinkhole.

## 2.3 The organisation (Kubernetes deployment)

The same zone graph, expressed as Kubernetes-native primitives instead of
multi-homed firewall containers — a pod has one network identity by design,
so the idiomatic translation is namespaces plus `NetworkPolicy`, not a forced
replica of the compose firewall containers.

| Zone (topology.json) | Namespace | Enforcement |
|---|---|---|
| internet | `cs-internet` | default-deny + explicit allows |
| dmz | `cs-dmz` | " |
| corp | `cs-corp` | " |
| datacenter | `cs-datacenter` | " |
| deception | `cs-deception` | " |
| egress | `cs-egress` | " |
| mgmt | `cs-control` | " |

Cilium (eBPF) is the CNI — chosen over the default `kindnet` (which enforces
no `NetworkPolicy` at all) and over the more common alternative, Calico,
specifically for **Hubble**, its flow-observability layer, which is the
natural k8s-native counterpart to the compose deployment's hand-rolled
`fw_agent` telemetry.

Every namespace gets a default-deny `CiliumNetworkPolicy` first, then one
explicit allow policy per edge in `config/topology.json`'s `policy_edges` —
generated, not hand-written, by `deploy/k8s/generate-policies.py`. An edge
marked `containment` (deception -> datacenter, deception -> internet) is
deliberately **not** translated into a rule at all: absence is the
enforcement, the same as the missing forward rule in the compose firewall.

Blocking an automated actor has no nftables set to write to in this
deployment, so `services/k8s_fw_agent` gives the decision plane's identical
`/v1/block` API a different backend: it maintains one
`CiliumClusterwideNetworkPolicy` with an `ingressDeny` rule naming every
currently-blocked address, applied through the Kubernetes API. Cilium
evaluates deny rules before allow rules regardless of which policy object
they came from — the same precedence the nftables `blocked` set has over its
own accept rules.

**Verified this session**, with real packets, not declared policy
(`deploy/k8s/verify.sh`, 8/8 checks):

| Path | Expected | Result |
|---|---|---|
| internet -> corp | blocked (no published service) | blocked |
| internet -> datacenter | blocked | blocked |
| deception -> datacenter | blocked (containment) | blocked |
| dmz -> corp, port 445 | blocked (restricted edge) | blocked |
| internet -> published dmz service | allowed | allowed |
| internet -> published deception service | allowed | allowed |
| corp -> datacenter | allowed (ordinary traffic) | allowed |
| deception -> corp, port 80 | allowed (the L3 hop) | allowed |

---

# 3. Component inventory

## 3.1 Control plane (every deployment target)

| Component | Role |
|---|---|
| `logger` | Append-only JSONL writer. System of record. Forwards each event to `decision`. |
| `decision` | Policy engine (P0 static / P1 utility / P2 intent-conditioned). Runs the operator classifier and pattern matcher per event, actuates blocks. |
| `gnn-scorer` | Graph model over the actor graph. Ships **untrained** — returns explicit priors until `./cs train-gnn` produces a real checkpoint. |
| `intelligence` | SIEM dashboard + milestone report API. Reads only the JSONL log and `config/topology.json`. |
| `fw-agent` (k8s only) | Cilium-backed implementation of the block/unblock API. |
| `zeek-ingest` | Tails Zeek's JSON logs into the canonical event envelope. |

## 3.2 Deception zone

| Component | Role |
|---|---|
| `sensor` (Zeek) | HASSH + JA4 fingerprinting on the wire. Shares one network namespace with the surfaces below it (a Pod, natively, in k8s; a compose `network_mode: service:` link in compose). |
| `ssh-surface` | asyncssh KEX. Authentication opens or stays closed per the current manifest. |
| `http-surface` | HTTPS-only (TLS-only posture — no plaintext HTTP). Login 401 unless escalated. |

## 3.3 Egress zone

| Component | Role |
|---|---|
| `sinkhole` | Stage-0 DNS + HTTP. Every name resolves here; every fetch is neutered and logged. Attached to neither firewall. |
| `sandbox` | The `interactive_operator` engagement surface once a manifest opens the shell. All capabilities dropped, read-only root, tight resource limits, DNS forced to the sinkhole. |

## 3.4 DMZ — real services

| Host | Address (routes to) | What it is |
|---|---|---|
| `www01` | www.nexuscorp.example | Real nginx + TLS marketing site |
| `mail01` | mail.nexuscorp.example | Real nginx + TLS webmail portal |
| `vpn01` | vpn.nexuscorp.example | Real nginx + TLS SSL-VPN portal |

## 3.5 Corporate LAN and datacenter — decoy and protected content

| Host | Zone | Kind |
|---|---|---|
| `dc01`, `fs01`, `erp01` | corp | Decoy content, reachable from deception on port 80 only (the L3 internal hop) |
| `wks01` | corp | Benign traffic generator — gives the classifier a non-attack background to discriminate against |
| `db01`, `bkp01` | datacenter | Protected. Never reachable from the deception zone, by any path. |

## 3.6 The demo actors

| Container | Behaviour | Expected classification |
|---|---|---|
| `attacker` | Fast port sweep, credential spray, no think-time, tool user-agents | `automated` — dropped at the firewall |
| `operator` | Hand-paced: reads a page, pauses, orients before acting, mistypes a command and corrects it | `interactive_operator` — escalated into a real shell |

Both run from the same network position, reach the same published address,
and are subject to the same firewall rules — the only variable is behaviour.

---

# 4. The bot-vs-human classifier

`lib/cs/operator.py` combines signals as log-odds contributions, not a single
threshold, so no one observation can decide the verdict alone:

| Signal | Evidence for | Weight |
|---|---|---|
| Known tool user-agent / SSH client string | machine | 2.0–2.2 |
| Sub-100ms sustained request rate | machine | 2.0 |
| Port sweep (8+ ports in under 60s) | machine | 2.1 |
| Credential-spray burst (6+ failures, tight window) | machine | 1.9 |
| Metronomic inter-event timing (low coefficient of variation) | machine | 1.8 |
| No think-time between auth success and first command | machine | 1.6 |
| Replayed command list (low uniqueness) | machine | 1.5 |
| A typo immediately followed by its correction | human | 2.4 |
| Orienting commands (`whoami`, `ls`, `pwd`, …) as most of the session | human | 1.2 |
| Multi-surface engagement (touches several telemetry families) | human | 1.0 |
| Irregular timing at human-scale gaps | human | 1.1 |

The combined probability decides the gate:

- `p_human` low, confidence high -> **BLOCK** — dropped at the firewall (compose: nftables set; k8s: `CiliumClusterwideNetworkPolicy` ingress deny).
- `p_human` mid -> **scripted** — held at L1, cheap to serve, still logged.
- `p_human` high -> **interactive_operator** — escalation to L2/L3 proceeds.

Blocking is a **per-actor** terminal, never a global posture: one blocked
scanner does not withdraw the deception surface from anyone else — an earlier
bug in this session did exactly that (`BLOCK` was briefly included in the
global-posture merge) and was fixed before it shipped.

---

# 5. Pattern matching and the graph model

`lib/cs/patterns.py` matches ordered sequences of events against a library of
named behaviours (perimeter sweep, credential attack, foothold, sandbox
evasion, tool staging, lateral movement, containment probe, …), each mapped
to an ATT&CK technique and a MITRE Engage activity code. Order matters — the
same events in a different order are a different behaviour — which is why
this is sequence matching and not a bag-of-events classifier.

These matches are also the **training signal** for the graph model
(`lib/cs/gnn_model.py`): there is no hand-labelled corpus of adversary intent
for a honeypot that has not been deployed, so pattern agreement stands in for
one. The model ships untrained and `score_graph()` refuses to produce a score
from random weights — it returns explicit priors and says so in its `model`
field. `scripts/train-gnn.py` / `./cs train-gnn` trains a real checkpoint on
captured traffic. Verified this session: after training on a short mixed
corpus (scan, credential attack, and a hand-paced session), the model scored
the bot at 99.99% `recon_scan` intent and the human at dominant
`lateral_movement`/`exploit_attempt` with 4× higher expected intelligence
gain — a real, trained signal, not a placeholder.

---

# 6. The dashboard

`http://127.0.0.1:18090/` (compose) — an intelligence-plane SIEM view reading
only the JSONL log and `config/topology.json`.

- **Overview** — event throughput, MITRE ATT&CK/Engage frequency, deception
  levels, experimental-arm comparison, and the **live network map**: every
  zone and host from the topology file, each tracked address placed in the
  zone its traffic actually originates from, colour-coded by the operator
  classifier's verdict.
- **Attack map** — pick a host, read its story left to right as numbered
  phases (infiltration -> execution -> discovery -> exfiltration), click any
  step for its technique, surface, and timestamp. Reachable directly by
  clicking an address anywhere else in the dashboard — the "IP as an entity"
  view: one click from a source address to everything it did.
- **Events** — the raw timeline and a live-tailing log stream.
- **Actors** — the full ranked actor table, capability badge included.

---

# 7. How to run this

## 7.1 Podman compose (single machine, full org topology)

```bash
git clone <this repo> && cd cybersnare
chmod +x cs scripts/*.sh
./cs bootstrap                 # enable podman user socket
./cs up                        # 21 containers: firewalls, org, control plane
./cs verify                    # health, surfaces, isolation, Zeek/HASSH/JA4

./cs attacker                  # automated profile — expect a firewall block
./cs operator                  # hand-paced profile — expect an engaged shell
./cs blocked                   # addresses currently dropped at each firewall
./cs monitor                   # live actor/transition activity
```

Dashboard: `http://127.0.0.1:18090/`. Raw log: `data/events/events.jsonl`.

To train the graph model on real traffic instead of shipping priors:

```bash
./cs observe                   # gate OFF, so a block doesn't cut the corpus short
./cs attacker && ./cs operator # or real traffic over a few days
./cs train-gnn
podman restart cs-gnn
./cs up                        # back to gate-on production mode
```

## 7.2 Kubernetes (kind + Cilium)

```bash
./cs k8s-cluster-up            # kind create cluster, default CNI disabled
./cs k8s-cilium-install        # Cilium + Hubble relay
./cs k8s-status                # wait for it — first-run image pulls are slow
./cs k8s-up                    # regenerate manifests from topology.json, deploy
./deploy/k8s/verify.sh         # 8 real containment checks

./cs k8s-attacker
./cs k8s-operator
./cs k8s-blocked
```

## 7.3 Verification checklist

| Command | What it proves |
|---|---|
| `./cs verify` | 16-point integration test: surfaces, isolation, telemetry |
| `./cs gate` | The §4.5 nineteen-property authentication gate |
| `./cs milestone` | Full milestone-1 readiness (lab + P4/P5 artefacts) |
| `deploy/k8s/verify.sh` | Real packet-level segmentation in the cluster |
| `./cs blocked` / `./cs k8s-blocked` | Live firewall blocklist state |

---

# 8. What is deliberately not built yet

Documented honestly rather than silently — see `docs/SCOPE-STATUS.md` for the
authoritative, continuously-updated version of this list.

- **Hubble -> canonical-event adapter.** Segmentation in the k8s deployment is
  fully enforced regardless; what's missing is turning Cilium's own flow
  visibility into this project's event schema, the way `fw_agent` does for
  the compose deployment's nftables counters.
- **L3 immerse** — a populated filesystem and a real internal hop beyond the
  decoy-port L3 hop already built.
- **Policy P3** — a learned policy over the collected three-arm corpus.
- **The two-server production deployment** (`deploy/org/`) — scaffolding
  only; nothing has been run against real hardware.
