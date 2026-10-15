# NetOsis — 7-day build plan (2026-10-16 → 2026-10-22)

Real lab (verified 2026-10-15): server → OPNsense (VM101). Kali (VM106) sits on
the FW WAN segment (vmbr0 tag 227) and treats the **FW WAN IP as the public IP**.
Everything else lives behind the FW on isolated `vmbr1` (no physical uplink).
Jbox (VM100) = lab/FW management only.

| Guest | VMID | IP | Role |
|-------|------|----|------|
| ent-web-01 | CT102 | 192.168.30.10 | Public-facing SSH HHP (`:2222`, WAN `:22` NAT) |
| finance-db-01 | CT104 | 192.168.10.10 | FIN HHP (reached only by lateral movement) |
| ops-srv-01 | CT105 | 192.168.20.10 | OPS HHP (reached only by lateral movement) |
| CyberSnare-Controller | VM103 | 192.168.40.10 | Ollama, telemetry collector, sandbox API, k3s |

`U` = you on Proxmox/OPNsense, `C` = code in this repo.

---

## Day 1 — Safety baseline + code hardening

- U: `pct set 105 -net0 name=eth0,bridge=vmbr1,firewall=1,gw=192.168.20.254,hwaddr=BC:24:11:B9:65:16,ip=192.168.20.10/24,tag=20,type=veth`
- U: Proxmox repos → `pve-no-subscription` (enterprise repo fails without a key).
- U: Datacenter → Firewall → Options: enable **only after** adding an IN rule allowing
  `8006`/`22` from the admin side (or you lock yourself out).
- U: VM106 Kali firewall: OUT `ACCEPT` → FW WAN IP; OUT `DROP` → everything else on
  tag 227 (keeps Kali away from the Jbox).
- U: OPNsense: GUI + SSH listen on LAN only; WAN has *no* allow rules yet; inter-VLAN
  default deny.
- C: ✅ LLM failure no longer kills the session; output sanitizer; `[llm]` mark off on
  deployed hosts; exec-channel (`ssh host 'cmd'`); login attempts logged (T1110/T1078);
  thread-safe graph + telemetry; arrow keys don't corrupt input.
- C: LLM response cache (same command + same state → same output) and only send
  *plausible binaries* to the LLM — junk words get an instant `command not found`.

## Day 2 — SOC + first honeypot live (internal)

- U: VM103: install Ollama, `OLLAMA_HOST=0.0.0.0:11434`.
- U/C: benchmark on this no-AVX CPU: `qwen2.5:0.5b`, `qwen2.5:1.5b`, `qwen2.5:3b`
  → pick the largest with p95 < ~4 s for 128 tokens.
- U: `scripts/deploy_to_lab.sh` → CT102 `/opt/netosis`, `.env` from
  `deception/hosts/ent-web-01.ssh.env`, enable `netosis-ssh`.
- U: CT102 Proxmox FW: IN allow `tcp/2222`; OUT allow `192.168.40.10:11434,8000`;
  OUT drop everything else (incl. Internet and `192.168.1.0/24`). Same pattern on 104/105.
- Done when: from Jbox `ssh admin@192.168.30.10 -p 2222` works and unknown commands
  are answered by Qwen.

## Day 3 — Public exposure (the "Internet" side)

- U: OPNsense → Firewall → NAT → Port Forward: WAN `tcp/22` → `192.168.30.10:2222`
  (auto-add the WAN rule). Nothing else on WAN.
- U: from Kali: `nmap -sV <FW-WAN-IP>` → only 22 open; `ssh admin@<FW-WAN-IP>`.
- C: ship telemetry to SOC (CT102 → VM103 HTTP collector `:8000/events`) so logs
  survive if the HHP is wiped; actor id = Kali's real IP (DNAT preserves source).
- Done when: a Kali session shows up in the SOC event log + attack graph.

## Day 4 — Lateral movement (makes CT104/CT105 meaningful)

Logic gap today: D01 "exposes" finance-db-01, but `ssh finance-db-01` in the fake shell
goes to the LLM, and a fake shell can't make real connections — so CT104/105 are
unreachable and unused.

- C: built-in `ssh <host>` in the command engine: allowed only after D01/D07 revealed
  the host. CT102 relays the attacker's keystrokes over a real SSH connection to
  CT104/CT105 `:2222`, passing the actor id, so the hop is real L3 traffic through
  OPNsense (visible in FW logs) and the graph gets a `lateral_movement` edge (T1021.004).
- U: OPNsense: allow **only** `192.168.30.10 → 192.168.10.10:2222` and
  `→ 192.168.20.10:2222`; deploy NetOsis on CT104/CT105 with their env files.
- Fallback if short on time: virtual hop inside the same process (no real traffic).

## Day 5 — Policy + ATT&CK correctness

- C: mapper looks at the *real* command (`sudo cat /etc/shadow` → T1003.008, pipes,
  `;`, `&&` split), fix `mkdir → T1036` (wrong technique), add T1021/T1105/T1059/T1053.
- C: behaviour-conditioned ladder: choose the deception by *what* the actor does
  (credential hunting → D03, network recon → D07, data browsing → D04/D05), not a
  fixed D01→D07 order by count.
- C: per-actor ladder state persists across reconnects (today it resets each session,
  and planted bait disappears when the host YAML is reloaded).

## Day 6 — Sandbox + k3s (scoped)

- U: VM103: `k3s` single node.
- C: sandbox API on VM103 `:8000`: `POST /fetch` — download URL in a throw-away k3s
  **Job** (no network except egress proxy, read-only rootfs, 60 s TTL), return
  sha256 / size / file type / YARA hits. **No detonation** of binaries.
- C: CT102 `.env`: `NETOSIS_SANDBOX_URL=http://192.168.40.10:8000`.
- Viva line: k8s is orchestration for disposable jobs, not the security boundary —
  the boundary is VM103 + FW rules.

## Day 7 — Real-server story + demo freeze

- U (optional): ENT-WEB-REAL `.30.40` nginx VM + WAN `:80` NAT; prove CT102 cannot
  reach it (Proxmox FW).
- C: SOC dashboard page: live sessions, attack graph, ATT&CK timeline.
- Run the full Kali scenario end-to-end, record it, update README/HANDOFF/vlans.yml.

## Cut list (if time runs out, drop in this order)

1. Real `.30.40` web VM 2. k3s (sandbox as plain container on VM103) 3. dashboard
(show `attack_graph.json` + JSONL instead) 4. real-relay lateral hop (use virtual).
