# SOC dashboard, attacker profiles, and how the LLM knows who is asking

Runs on the SOC VM (192.168.40.31:8000) next to the LLM. Honeypots ship telemetry
to it; analysts open it from the Jbox browser. Nothing here ever talks back to an
attacker.

```text
 attacker ──ssh──► honeypot CT ──(every event, profile, graph, heartbeat)──► controller :8000
                   local telemetry.jsonl                                      ├─ SocStore (merge, alerts, actors, ATT&CK, graph)
                   (source of truth)                                          ├─ /api/*  JSON for the dashboard
                                                                              ├─ /api/stream  live events (SSE)
                                                                              └─ /  the dashboard (soc/dist)
```

## Who is asking? (how the LLM tells attackers apart)

1. **Identity.** Every SSH connection becomes a `Session` with `actor_id = "actor-<source ip>"`
   (`scripts/ssh_honeypot.py`). Each connection also loads its **own copy** of the fake host, so
   two attackers on the same honeypot cannot see each other's files.
2. **Profile.** `VerticalSlicePipeline` loads/saves one `ActorProfile` per `actor_id`
   (commands, ATT&CK techniques, risk, created files, hosts, timeline) in `data/profiles/`.
3. **Persona.** `deception/runtime/persona.py` turns that history into a plain label
   (*Scanner, Explorer, Credential hunter, Dropper, Entrenching, Covering tracks, Lateral mover,
   Brute-forcer*). Each label lists the exact commands that triggered it.
4. **Context for the LLM.** Before an unknown command reaches the model,
   `rag/ingest.py` builds the evidence set. The current attacker's profile document is
   force-pinned (`deception/llm/rag.py:_forced_mutation_hits`) and reads:
   *"CURRENT ATTACKER on this shell session — attribute ALL shell state to them. Behaviour so
   far: credential hunter — this attacker is looking for passwords and keys. Risk HIGH …"*.
   Other attackers appear only as *"OTHER attacker (do NOT mix their files/packages into this
   shell's replies)"* (switch off with `NETOSIS_RAG_MULTI_ACTOR=0`).
5. **Cache is keyed per host and user, never per attacker**, so a cached answer can never leak
   one attacker's state to another (mutating commands are never cached).

The same `classify()` function feeds the dashboard card and the LLM prompt, so they cannot disagree.

## Run it

On VM103 (after `git pull`):

```bash
cd /opt/netosis && bash scripts/soc-dashboard-setup.sh
```

It generates the ingest token, installs `netosis-controller.service`, and prints the dashboard
URL plus the one line to run on each honeypot:

```bash
NETOSIS_INGEST_TOKEN=<token> bash /opt/netosis/scripts/lab-bootstrap-remote.sh ent-web-01
```

Open `http://192.168.40.31:8000/` from the Jbox browser. No Node is needed on the server:
`soc/dist` is built and committed.

### Rehearse without an attacker

```bash
python3 scripts/soc_demo.py --controller http://127.0.0.1:8000 --token <token> --speed 2 [--loop]
```

It replays four stories (brute-forcer, scanner, credential hunter who pivots to finance-db-01,
dropper) through the **real** engine, mapper, policy and persona code and ships them exactly as a
honeypot does. finance-db-01 and ops-app-01 start "powered off" and finance-db-01 comes up at the
moment of the pivot, which is the auto-wake story.

## Node agents (live topology)

Every node runs `agent/netosis_agent.py` as the `netosis-agent` systemd service
(`ops/systemd/netosis-agent.service`). Every 10 s it **pushes** CPU, memory, disk, network rate,
listening ports, the state of its NetOsis services, and its open TCP connections to
`POST /v1/agent`. The Network Intelligence page and the topology are built from those
reports, so they show what is connected **right now**: attacker → honeypot, honeypot → honeypot
pivots, and telemetry/LLM traffic to the SOC.

Why an attacker can't reach or tamper with it:

* **No listening socket.** The agent only makes outbound POSTs to the controller and ignores the reply.
  `ss -ltnp` shows nothing for it.
* **A separate user.** It runs as `netosis-agent`, not as the honeypot's `netosis` user. Its code is a
  root-owned copy in `/usr/local/lib/netosis-agent/`, and its token is in `/etc/netosis/agent.env`
  (root, 0600). systemd reads that file before dropping privileges.
* **The attacker only sees the fake shell.** An SSH attacker talks to the emulated shell and never
  gets a real process on the CT.
* **systemd hardening:** no capabilities, `NoNewPrivileges`, read-only filesystem, and limits of 64 MB and 10 % CPU.
* **Token-guarded on the controller.** `/v1/agent`, `/v1/ingest` and `/v1/pivot/wake` all require
  `X-Netosis-Token`. Reports are shape-checked and size-capped.

Install (already done by `lab-bootstrap-remote.sh` and `soc-dashboard-setup.sh`):

```bash
NETOSIS_INGEST_TOKEN=<token> bash scripts/agent-install.sh ent-web-01 honeypot 102
bash scripts/agent-install.sh controller soc          # on the SOC VM
python3 agent/netosis_agent.py --once                  # print one report, send nothing
```

Firewall: each node needs outbound TCP to `192.168.40.31:8000`, nothing inbound.

## Modules

| Module | Answers | Data source |
|--------|---------|-------------|
| Overview | KPIs, globe, live feed, topology, tactic mix, recent attack paths | all endpoints below |
| Global Attack Map | Where attacking networks are registered (approximate) | `/api/geo` |
| Live Sessions | Every SSH connection; **replay** of what the attacker typed, what the honeypot answered, which tactic each step reached, and which deception rung fired | `/api/sessions`, `/api/events?session=` |
| Attack Graph | Attackers → honeypots → ATT&CK techniques, pivots between honeypots | `/api/graph` |
| MITRE ATT&CK | Only the techniques the NetOsis mapper can emit; drill down to the exact commands | `/api/attack` |
| Deception Engine | The D01–D07 ladder, thresholds from `policy/rules/baseline.yml`, every fired response with its score and trigger | `/api/deception` |
| Telemetry | Searchable, filterable raw events, JSON inspector, CSV/JSON export of exactly what is shown | `/api/events` |
| Network Intelligence | Documented VLANs plus live state from node agents (load, services, open connections), live flows, observed pivots | `/api/network`, `/api/agents` |
| AI Intelligence | Ollama reachability, share of commands the LLM answered vs the deterministic engine | `/api/ai` |
| System & Policies | Sensor heartbeats, controller health, what is (not) configured | `/api/health` |

Every endpoint takes the same `window` (`1h`, `24h`, `7d`, `all`), so one screen never mixes time ranges.

## Data integrity rules (enforced in code, covered by tests)

* **KPI definitions** are returned by `/api/overview` and shown on hover. Observed attacks = distinct SSH
  connections (session IDs), including failed-login-only ones; active sessions = honeypot heartbeats;
  high-risk = credential access, persistence, execution, payload transfer, lateral movement, canaries.
* **Private, lab and reserved IPs are never geolocated** (Kali on 172.30.227.0/24 shows as
  "Lab / internal"). Public IPs are placed only if a MaxMind GeoLite2 database is installed
  (`data/geoip/GeoLite2-City.mmdb` + `python3-maxminddb`); otherwise they are listed as "not geolocated".
* **Arcs** are drawn only when both ends are grounded: a located source and the lab's configured location
  (`NETOSIS_SITE_LAT/LNG` in `controller/.env`).
* **Demo data**: `scripts/soc_demo.py` sends batches flagged `"demo": true` from RFC 5737 documentation
  addresses. The UI shows a *Demo data* badge, tags every demo row, and places demo sources only at
  illustrative fixture cities (`controller/geo.py`). Demo arcs end at a demo lab location, never a live one.

## Security notes

* **Ingest is write-only and token-guarded** (`X-Netosis-Token`, constant-time compare). The read
  API is unauthenticated, so firewall it: allow VM103:8000 **in** from the honeypot IPs (ingest) and
  the Jbox LAN leg `192.168.1.10` (dashboard) only. See `ops/SERVER_RUNBOOK.md`.
* Ingest stores at most 5,000 events in memory (and an append-only `data/soc/events.jsonl`); result
  text is truncated to 1,500 characters per event.
* The shipper can never slow or break an attacker session: it is a background queue, drops on
  failure, and the honeypot's own `telemetry.jsonl` stays the source of truth.

## Changing the UI

```bash
cd soc && npm ci
npm run dev          # http://localhost:5173, proxies /api to a local controller on :8000
npm run build        # type-checks, writes soc/dist — commit it (the SOC VM needs no Node)
```

Stack: React + TypeScript + Vite + Tailwind v4, TanStack Query/Table, React Flow, ECharts (tree-shaken),
react-globe.gl, Motion, Lucide, Geist (self-hosted — the lab has no Internet). Light theme; colour is
semantic only (severity, tactic). Country shapes for the globe are bundled in `soc/public/geo/`
(Natural Earth 1:110m, validated against H3).
