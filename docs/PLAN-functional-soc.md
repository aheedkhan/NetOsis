# Plan: make the SOC dashboard fully functional

Status: planned 2026-10-19, on branch `feat/soc-dashboard-agents`. Today the dashboard **shows**
real data, but almost nothing in it **does** anything. This plan turns each "for show" element
into a working feature, then finishes the remaining honeypot work.

## Ground rules (carry over)

* Every number traces to a real event; demo data is always labelled.
* Honeypots and agents never open a port for the SOC. The controller sends instructions
  **in the reply to a heartbeat or agent report** (pull model), so nothing new listens on a honeypot.
* Each dashboard action must be one of:
  * authenticated, logged (who, what, when) and reversible, or
  * explicitly confirmed by the analyst.
* Verify every UI change in the browser (Playwright screenshots), not just with `tsc`.

## What is "for show" today

| Element | Today | Should do |
|---|---|---|
| Profile corner "aheed / Administrator ▾" | static text | real analyst login, menu (log out, change password) |
| Read API `/api/*` | open to anyone who reaches :8000 | requires a login session |
| Bell + count | links to a telemetry filter | alert inbox: unread / acknowledged / closed |
| Alerts | computed, no workflow | triage: assign, status, notes, close |
| Deception Engine page | read-only ladder | per-honeypot thresholds, manually fire/disable a rung |
| Honeypot on/off | only auto-wake on pivot | power buttons + idle auto power-off |
| Live session | replay after the fact | watch live; **end session**; quarantine source IP |
| AI page "candidates to emulate" | a list | "promote" → save as a deterministic answer |
| `/v1/sandbox/run` | 501 stub | sandbox gate → k3s job (POC) |
| Exfiltration | not detected | detect + alert (+ deception response) |
| History | 5,000 events in memory → trends show "no earlier data" | SQLite store, real trends over days |
| Map | demo cities only | MaxMind GeoLite2 + lab location for real IPs |
| Reports | CSV/JSON of telemetry | per-attacker incident report (PDF/HTML) |
| Notifications | none | webhook/email on critical alerts |

## Phases

### Phase 1: Foundations (do first, everything else depends on it)
1. **Durable store.** SQLite at `data/soc/netosis.db` (stdlib `sqlite3`).
   * Tables: events, sessions, alerts, agents, audit, users.
   * Migrate from `events.jsonl` on first start.
   * Keep the in-memory cache for the live views.
   * *Done when:* the trends show real "vs previous 24h" after a restart, and the history survives reboots.
2. **Analyst auth.**
   * Local users in SQLite (scrypt hashes).
   * Login page, HttpOnly + SameSite=Strict session cookie, logout, CSRF token on POSTs.
   * `scripts/soc-user.py add <name>` creates the first account.
   * The ingest/agent endpoints keep using the lab token.
   * *Done when:* `/api/*` returns 401 without a session, and the profile corner shows the logged-in user with a working menu.
3. **Audit log.** Every dashboard action is written to `audit` and shown on the System page.

### Phase 2: Triage workflow
4. **Alert inbox.**
   * The bell opens a drawer with unread alerts.
   * Each alert gets a status (new → investigating → closed), an assignee and notes.
   * Filters on the Telemetry and Sessions pages honour alert links.
5. **Notifications.** Optional webhook (Slack/Discord/ntfy) or SMTP for CRITICAL alerts; configured in `controller/.env`.
6. **Incident report.** "Export report" on a session or attacker produces an HTML/PDF covering:
   * timeline,
   * commands,
   * ATT&CK techniques,
   * deception responses,
   * pivot path,
   * IOCs.

### Phase 3: Active response (pull model, honeypot-side enforcement)
7. **Action queue.**
   * The controller stores pending actions per sensor.
   * The honeypot heartbeat (every 20 s, or sooner while a session is live) receives them in the reply, executes them and reports the result.
8. **End session / quarantine IP.** The honeypot closes that SSH channel and refuses the IP for N minutes. The dashboard buttons sit on the Sessions detail and the globe card.
9. **Deception control.**
   * Edit rung thresholds per honeypot (validated, written through the action queue, audited).
   * "Fire rung now" / "disable rung" per session.
10. **Power control.**
    * Buttons on the System and Network pages call the Proxmox API (CTID allowlist {102, 104, 105}, confirm dialog).
    * **Idle auto power-off:** finance-db-01 and ops-app-01 power off after N minutes with no sessions, and wake again on a pivot.
11. **Promote LLM answers.** On the AI page, approve a cached LLM answer and save it as a deterministic response (host + command); it is audited.

### Phase 4: Detection and sandbox
12. **Exfiltration detection.**
    * Rules on the command stream: `scp`/`rsync`/`curl -T`/`nc` to outside, base64 or tar of sensitive paths, large `cat` of canary files.
    * Agent-side: unusual outbound bytes or connections from a honeypot.
    * New ATT&CK techniques: T1048, T1041, T1567.
    * Output: an alert plus a deception response (fake transfer success).
13. **Sandbox gate.**
    * The LLM classifies each unknown command (safe / needs execution / block) before anything runs.
    * `/v1/sandbox/run` queues approved commands.
    * The result flows back into the session.
14. **k3s sandbox POC (last).** One throwaway pod per command, no network, read-only root, a time limit, results captured. Runs on the SOC VM or a dedicated sandbox VLAN.

### Phase 5: Real-lab rollout and verification
15. Deploy the branch to VM103 and CT102/104/105 (`soc-dashboard-setup.sh`, `lab-bootstrap-remote.sh`).
16. Firewall rules:
    * node → 192.168.40.31:8000 only;
    * honeypot → honeypot :2222;
    * no honeypot → Internet after the clone;
    * dashboard reachable from the Jbox only.
17. VM103 → Proxmox API (172.30.226.7:8006): confirm the route and the restricted token, then test auto-wake.
18. Live test from Kali through the WAN: attack → globe/feed/session replay → pivot to finance-db-01 (auto-wake) → live topology lines → end-session button.
19. GeoLite2 + `NETOSIS_SITE_LAT/LNG` for real public-IP mapping (needs a free MaxMind account).
20. Playwright end-to-end tests in the repo (`soc/e2e/`), run in CI or before each deploy.

## Suggested order for the next session

Phase 1 (store + auth + audit) → Phase 2 #4 (alert inbox) → Phase 3 #7–#8 (action queue + end
session). These turn the biggest "for show" parts into working features. Exfiltration, the
sandbox gate and k3s come after that.

## Open decisions for the user

* Analyst accounts: one admin, or several analysts with roles (admin / viewer)?
* Notifications: which channel (Discord, Slack, ntfy, email)?
* Idle power-off timeout for finance-db-01 / ops-app-01 (e.g. 15 min)?
* Sandbox placement: SOC VM, or a new isolated sandbox VLAN?
