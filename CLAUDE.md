# CLAUDE.md: NetOsis handoff

Read this first. It is the single source of truth for what NetOsis is, its current state,
the rules for working on it, and what to do next. Last updated **2026-11-12**.

## What NetOsis is

NetOsis is an adaptive cyber-deception platform. Its parts:

* **Honeypots.** High-interaction SSH honeypots with an emulated, deterministic fake shell. An LLM answers only the commands the shell doesn't know.
* **Node agents.** Each honeypot also runs an agent that reports telemetry.
* **SOC controller.** It takes signed telemetry from the nodes, maps it to MITRE ATT&CK, builds attack graphs and actor profiles, and drives the deception ladder (D01–D07).
* **SOC dashboard.** A React app (`soc/`) served by the controller.

The pipeline:

```
network isolation → telemetry → actor profile → attack graph → ATT&CK → policy → adaptive deception
```

**Core rule:** the LLM is never the controller. Host state is YAML/JSON, and common commands are answered
by the deterministic engine (`deception/command_engine`). Policy validates every adaptive action.

## Where things are

| Path | What |
|---|---|
| `scripts/ssh_honeypot.py` | the SSH honeypot (fake shell, ssh relay for lateral movement, telemetry shipping) |
| `deception/` | command engine, virtual hosts (`hosts/*.yml`, `*.ssh.env`), LLM fallback, lore, runtime sandbox stub |
| `controller/app.py`, `soc.py` | SOC controller: dashboard `:8000`, ingest `:8001`, SOC state |
| `controller/signing.py` | per-node HMAC request signing (replay window 90 s, identity binding, allowlist) |
| `controller/proxmox.py` | Proxmox API client used for honeypot auto-wake on pivot |
| `agent/netosis_agent.py` | node agent (pull model: never listens) |
| `soc/` | dashboard source (React/Vite/Tailwind v4). `soc/dist` **is committed** so servers need no Node |
| `scripts/lab-rollout.sh`, `lab-verify.sh`, `node_keys.py` | deploy to / verify the Proxmox lab |
| `scripts/soc_demo.py` | replays labelled demo attacks (RFC 5737 IPs, `"demo": true`) |
| `docs/DEPLOY-lab.md` | how the real lab is deployed: what runs where, the firewall rule table, logs |
| `docs/LOCAL-LAB.md` | **next job:** rebuild the whole lab (FW + VLANs + nodes + SOC + attacker) on one PC, no server |
| `docs/PLAN-functional-soc.md` | roadmap that makes the dashboard operational (store, auth, inbox, actions…) |
| `ARCHITECTURE.md`, `SECURITY.md` | design and security assumptions |

## Commands

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python -m pytest -q                     # 98 passed on 2026-11-12
.venv/bin/python scripts/ssh_honeypot.py --port 2222   # ssh admin@127.0.0.1 -p 2222 (admin123)
NETOSIS_INGEST_TOKEN=demo .venv/bin/python controller/app.py      # http://127.0.0.1:8000
.venv/bin/python scripts/soc_demo.py --token demo --speed 4 --loop
cd soc && npm ci && npm run build                 # after any UI change; commit soc/dist
```

## Current state (2026-11-12)

Done and committed:
* honeypot with lateral movement between the three honeypots;
* LLM cache and junk-command filter;
* SOC dashboard on real data (globe, sessions replay, attack graph, ATT&CK, deception, telemetry, network, system);
* per-node HMAC-signed ingest on a separate port;
* fake shell that hides every trace of the lab (enforced by `tests/unit/test_shell_hides_lab.py`);
* rollout/verify scripts for the Proxmox lab;
* journald/logrotate/seccomp hardening.

All of it was tested end to end in podman containers (SOC + honeypot + attacker), not yet on the real server.

Not done yet: everything in `docs/PLAN-functional-soc.md` (the durable SQLite store, analyst
login, audit log, alert inbox, action queue, end session, exfiltration detection, sandbox gate).

**The plan has changed.** There is **no server** for now. The next job is to build the whole architecture
locally on one Linux PC, firewall included, following `docs/LOCAL-LAB.md`. After that, continue
with `docs/PLAN-functional-soc.md`.

## What to do next (in order)

1. **Local lab.** Implement `docs/LOCAL-LAB.md` tasks L1–L7: libvirt networks, an OPNsense VM, the SOC VM, three honeypot VMs, a Kali VM, a local rollout, and the end-to-end attack test.
2. **Phase 1 of `docs/PLAN-functional-soc.md`:** SQLite store, then analyst auth, then the audit log.
3. **Phase 2 #4:** alert inbox.
4. **Phase 3 #7–#8:** action queue (pull model), then end session / quarantine IP.
5. Then exfiltration detection, the sandbox gate, and the k3s sandbox proof of concept.

## Rules for working on this repo (from the user)

* **Git identity:** commit and push only as `aheedkhan <aheedkhan03@gmail.com>`; the remote is `aheedkhan/NetOsis`.
  * The user has a second GitHub account. Never use it here.
  * Check `git config user.email` before committing.
  * Commit only when the user asks.
* **Framing:** describe the lab only as *VPN → server → firewall*, with the lab isolated behind the FW.
  * Don't mention any university, campus or institution network in code or docs.
  * The FW WAN segment is the "lab public network", and Kali treats the FW WAN IP as the public IP.
* **Every number is grounded.**
  * Each figure on the dashboard traces to a real event.
  * Never fabricate telemetry. Demo data comes only from `scripts/soc_demo.py` and is always labelled.
  * No geolocating private IPs. Globe arcs appear only when both ends are grounded.
* **UI taste:** the dashboard is a LIGHT theme, "precision cybersecurity meets Apple-level craft".
  * Porcelain `#F5F7FB` canvas, white surfaces, 1px borders, frosted glass only on floating panels.
  * Fonts: Geist and Geist Mono.
  * Colour is semantic only (severity, ATT&CK tactic).
  * References: `docs/NetOsis Cybersecurity Dashboard.png` and `docs/NETOSIS_UI_RESOURCES.md`.
  * The user rejected an earlier dark/flat design.
  * Verify UI changes with headless Chromium screenshots at 1536, 1280 and 390 px. For WebGL use `--use-angle=swiftshader --enable-unsafe-swiftshader`.
  * TanStack Table must stay on **v8** (npm defaults to v9, which has a different API).
* **Security model is not negotiable:**
  * Honeypots and agents never open a port for the SOC; the controller only replies to node requests (pull model).
  * The master ingest token never leaves the SOC; each node has its own derived key.
  * Nothing the attacker can see in the fake shell may reveal NetOsis, the agent, `192.168.40.x` or `:8001`.
* **Power control** (stop, idle auto-off, dashboard power buttons): **the user implements this themselves.**
  * Don't build it unless asked.
  * Auto-wake on pivot already exists (Proxmox backend).
* The dashboard design skills (`.claude/`, `.agents/`, `skills-lock.json`) are gitignored local tooling and may be missing on a new PC. Install them on request; they are not needed to build.
* `HANDOFF.md`, `COORDINATION.md` and `*.xlsx`/`*.docx` are personal local files (gitignored). This file replaces `HANDOFF.md`.

## Real lab reference (for when a server is available again)

The Proxmox host has one uplink.

| Guest | Role | Network |
|---|---|---|
| VM101 OPNsense | firewall | WAN `172.30.227.100/24` (gw `.254`), the lab "public IP"; LAN trunk on an isolated bridge: `192.168.1.0/24` mgmt plus VLANs 10/20/30/40 (gw `.254`) |
| VM100 Jbox | FW/lab management only | `192.168.1.10` |
| VM106 Kali | attacker, deliberately **outside** the FW | WAN segment |
| CT102 ent-web-01 | public honeypot (WAN `:22` NAT → `:2222`) | `192.168.30.10` |
| CT104 finance-db-01 | honeypot | `192.168.10.10` |
| CT105 ops-app-01 | honeypot | `192.168.20.10` |
| VM103 SOC controller | SOC (+ Ollama) | `192.168.40.31` |

The CPU has no AVX, so Ollama on the server uses small Qwen models. Firewall rules: `docs/DEPLOY-lab.md` §4.
`docs/LOCAL-LAB.md` reproduces the same addressing locally, so the docs and rules apply unchanged.
