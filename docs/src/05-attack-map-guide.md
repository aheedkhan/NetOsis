# CyberSnare — Attack Map Guide

**Document:** Attack flow diagram & dashboard operator guide  
**Version:** 1.0 · September 2026  
**Audience:** Lab operators, FYP viva, SOC reviewers

---

## 1. What is the Attack Map?

The **Attack Map** is a dedicated tab in the CyberSnare SOC dashboard (`http://127.0.0.1:18090/` → **Attack map**). It shows **what one attacker host did**, in **time order**, using plain language instead of raw log codes.

| Question | Answer |
|----------|--------|
| Is it real data? | **Yes** — built from `data/events/events.jsonl` (same system of record as the SIEM). |
| Who is an "attacker host"? | Any machine that generated telemetry (e.g. Kali at `10.200.3.50`, or your laptop at `127.0.0.1`). |
| How do I open it? | Dashboard → top nav → **Attack map** → pick a host on the left. |

---

## 2. How to read the flow (30 seconds)

```
┌─────────────────────────────────────────────────────────────────┐
│  HOW TO READ                                                     │
│  1. Pick a host on the left (e.g. "Kali attacker")                │
│  2. Read TOP → BOTTOM — each coloured block is one attack phase │
│  3. Inside each block, follow arrows LEFT → RIGHT for steps       │
│  4. Click any step card for technique, surface, and timestamp     │
└─────────────────────────────────────────────────────────────────┘
```

**Reading direction:** Think of a comic strip or incident timeline — start at the orange **Starts here** card, then move down through phases 1–4.

---

## 3. Network path strip (Zenmap-style)

At the top of the attack story you see a horizontal path:

```
  [ Attacker host ]  →  [ Egress network ]  →  [ Deception VLAN ]  →  [ Honeypot target ]
     10.200.3.50           10.200.3.0/24         10.200.2.0/24          10.200.2.10
```

| Hop | Meaning |
|-----|---------|
| **Attacker host** | Where the probe originated (Kali container or your laptop). |
| **Egress network** | Outbound VLAN — malware callbacks and DNS egress are monitored here. |
| **Deception VLAN** | Internal lab network where honeypot services live. |
| **Honeypot target** | The fake server (`10.200.2.10`) — SSH, HTTPS, shell surfaces. |

Highlighted hops show where this host's traffic was seen most often.

---

## 4. Attack phases (Caldera-style)

CyberSnare groups each step into one of four phases. This matches how red-team tools (e.g. MITRE Caldera) organise an operation.

### Phase 1 — Infiltration (blue)

**What happened:** Reconnaissance and initial access attempts.

| Typical steps | MITRE | Honeypot surface |
|---------------|-------|------------------|
| Port / service scan | T1595 Active Scanning | Zeek sensor |
| SSH login attempt | T1078 Valid Accounts | SSH honeypot |
| HTTPS login attempt | T1078 Valid Accounts | Web portal |

At **L1 (Attract)** auth is **closed** — logins fail but attempts are logged.  
At **L2 (Engage)** auth **opens** — guest can log in to the restricted shell.

### Phase 2 — Execution (green)

**What happened:** Commands run inside the restricted shell after successful login.

| Typical steps | MITRE | Notes |
|---------------|-------|-------|
| `whoami`, `ls`, etc. | T1059 Command Interpreter | Logged per command |
| Spray / automation | T1059 | Red-team scripts |

### Phase 3 — Discovery (purple)

**What happened:** Attacker checks whether the environment is real or a VM/honeypot.

| Typical steps | MITRE | Notes |
|---------------|-------|-------|
| `systemd-detect-virt` | T1497 VM/Sandbox Evasion | Raises suspicion score |
| `/proc/cpuinfo`, `dmesg` | T1007 System Service Discovery | Triggers policy toward BURN |

### Phase 4 — Exfiltration / C2 (red)

**What happened:** Outbound malware callback — **caught by the sinkhole**.

| Typical steps | MITRE | Notes |
|---------------|-------|-------|
| DNS lookup `malware.example` | T1071 Application Layer Protocol | Resolves to sinkhole `10.200.3.2` |
| HTTP fetch payload | T1105 Ingress Tool Transfer | Returns neutered `echo sinkholed` |

---

## 5. Full operation flow diagram

Example after `./cs attacker` (Kali → honeypot → BURN):

```
                    CYBERSNARE ATTACK FLOW
                    ======================

   [ Kali 10.200.3.50 ]
            │
            │ ① Infiltration
            ▼
      ┌───────────┐     ┌───────────┐     ┌───────────┐
      │ nmap scan │ ──► │ SSH probe │ ──► │ HTTPS try │
      └───────────┘     └───────────┘     └───────────┘
            │
            │ ② Execution (L2 engage)
            ▼
      ┌───────────┐     ┌───────────┐
      │ SSH login │ ──► │ shell cmd │
      │  guest    │     │ whoami…   │
      └───────────┘     └───────────┘
            │
            │ ③ Discovery
            ▼
      ┌───────────┐     ┌───────────┐
      │ VM check  │ ──► │ proc read │
      └───────────┘     └───────────┘
            │
            │ ④ Exfiltration / C2
            ▼
      ┌───────────┐     ┌───────────┐
      │ DNS sink  │ ──► │ HTTP sink │
      │ malware…  │     │ stage0.sh │
      └───────────┘     └───────────┘
            │
            │ Policy: BURN
            ▼
      [ SSH/HTTPS hidden — evidence frozen ]
```

---

## 6. Deception levels vs attack map

The posture badge (top right) shows the **current global deception level**:

| Level | Name | What attacker sees | Map behaviour |
|-------|------|-------------------|---------------|
| **L1** | Attract | Ports open, login **denied** | Infiltration steps dominate |
| **L2** | Engage | Login **works**, restricted shell | Execution + discovery appear |
| **L3** | Immerse | Deeper fake network (org deploy) | More lateral-style steps |
| **BURN** | Burn | SSH/HTTPS **hidden** | Surfaces frozen; sinkhole stays |

Escalation can be manual (`./cs set-level L2`) or automatic (policy P1 after enough engagement).

---

## 7. Step card fields

When you click a step:

| Field | Meaning |
|-------|---------|
| **MITRE technique** | ATT&CK ID + name (e.g. T1595 Active Scanning) |
| **What they touched** | Which honeypot surface (SSH, shell, sinkhole, …) |
| **Honeypot level** | L1/L2/BURN at time of event |
| **When** | UTC timestamp from JSONL |

---

## 8. Lab commands cheat sheet

```bash
./cs up                    # Start base stack
./cs up-adaptive           # P1 policy + GNN (Arm B)
./cs attacker              # Kali auto: recon → L2 → BURN
./cs reset-lab             # Back to L1 after BURN
./cs set-level L2          # Open shell auth manually
./cs verify-l2             # Confirm engage works
```

Dashboard: `http://127.0.0.1:18090/`  
Download this guide: **Attack map** tab → **Download PDF guide**

---

## 9. Data path (how the map is built)

```
  Attacker action
        │
        ▼
  Honeypot / Zeek / sinkhole services
        │
        ▼
  Logger → data/events/events.jsonl
        │
        ▼
  Intelligence API (/v1/graph, /v1/graph/actor)
        │
        ▼
  Attack Map UI (phases + steps)
```

No separate database — the JSONL file is the system of record.

---

## 10. Troubleshooting

| Problem | Fix |
|---------|-----|
| Empty host list | Run `./cs attacker` or `./cs redteam` to generate traffic |
| "No attack steps" | Host only has background Zeek noise — pick **Kali attacker** |
| Map slow (first load) | First API call caches JSONL tail; refresh is fast |
| Stuck on BURN | `./cs reset-lab` then re-run scenario |

---

*CyberSnare FYP · Milestone 1 · Attack Map Operator Guide*
