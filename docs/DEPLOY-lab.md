# Deploying NetOsis on the lab server

How the code gets onto the server, what runs where, how the nodes reach the SOC
safely, and where every log ends up.

```
Kali / Internet ──► OPNsense WAN :22 ──NAT──► ent-web-01 :2222 (fake shell)
                                                 │  ssh relay :2222
                                                 ├──► finance-db-01 / ops-app-01
                                                 │
   every CT:  netosis-ssh + netosis-agent ──signed POST──► SOC VM :8001 (ingest only)
                                                           SOC VM :8000 (dashboard) ◄── Jbox browser
```

## 1. What is installed where

| Machine | Installed by | Services | Listens on | Files |
|---|---|---|---|---|
| **VM103** SOC controller `192.168.40.31` | `scripts/soc-dashboard-setup.sh` (run on it) | `netosis-controller`, `netosis-agent`, `ollama` | `:8000` dashboard, `:8001` ingest, `:11434` LLM | `/opt/netosis` (repo), `controller/.env` (master secret), `data/soc/` |
| **CT102** ent-web-01 `192.168.30.10` | `scripts/lab-rollout.sh` (from the Proxmox host) | `netosis-ssh`, `netosis-agent` | `:2222` only | `/opt/netosis/.env` (own key), `data/`, `/etc/netosis/agent.env` |
| **CT104** finance-db-01 `192.168.10.10` | same | same | `:2222` only | same |
| **CT105** ops-app-01 `192.168.20.10` | same | same | `:2222` only | same |
| **Proxmox host** | nothing permanent | — | — | a clone in `/root/netosis`, used to push code into the CTs |
| **OPNsense** | you, by hand (rules in §4) | — | — | — |

The agents and honeypots never listen for the SOC. The controller never connects to a CT;
every connection starts from the node, so there is nothing on a CT for anyone to reach
except the fake SSH on `:2222`.

## 2. How a node talks to the SOC securely

1. **The master secret stays on VM103.** It is `NETOSIS_INGEST_TOKEN` in `controller/.env` (mode 600), and it is never copied to a CT.
2. **Each node has its own key,** derived from the master: `key = HMAC(master, "netosis-node:" + name)`.
   * `python3 scripts/node_keys.py` prints them.
   * `soc-dashboard-setup.sh` writes them to `/root/netosis-node-keys.env`.
3. **Every write is signed,** with `HMAC(key, timestamp, path, sha256(body))`.
   * The key itself is never sent.
   * A captured request goes stale after 90 s, and the controller refuses a repeat within that window (replay check).
   * Changing a byte of the body breaks the signature.
4. **Identity binding.** A node can only report as itself. If ent-web-01's key posts as finance-db-01, the controller answers 403 and logs it on the System page under *Refused writes*.
5. **Allowlist.** `NETOSIS_NODES` in `controller/.env` lists the only node names that may write. To revoke a node, remove its name.
6. **Two ports.**
   * **Ingest `:8001`** serves `/v1/*` only: no dashboard, no data.
   * **Dashboard `:8000`** refuses node writes, except from loopback for `soc_demo.py`.
   * The firewall gives the honeypot VLANs `:8001` only.
7. **Inside each CT, the secrets are split by user.**
   * The agent's key is in `/etc/netosis/agent.env`: root 600, read by systemd before it drops to the `netosis-agent` user.
   * The honeypot's copy is in `/opt/netosis/.env`: `netosis` 600.
   * The honeypot process cannot read the agent's file. `lab-verify.sh` checks this.

**What changes for an attacker.** They sit inside an emulated shell, so nothing they type runs
on the CT. The fake `ps`, `ss`, `netstat`, `systemctl`, `env`, `/proc/net/tcp`, `ls /etc` and so on
show a plain Ubuntu server: no NetOsis, no agent, no `192.168.40.x`, no `:8001`. This is enforced
by `tests/unit/test_shell_hides_lab.py`, which also runs on every CT through `lab-verify.sh`.

**If someone escapes the fake shell:**
* They hold only that CT's key, which can write telemetry *as that CT* and nothing else.
* The firewall gives them `:8001` on the SOC, and the dashboard port and the other VLANs are closed to them.
* Every refused write shows up on the System page with its source IP, flagged **INSIDE LAB**.

## 3. Install order

```bash
# --- VM103 (SOC), as root -------------------------------------------------
git clone https://github.com/aheedkhan/NetOsis.git /opt/netosis   # or: cd /opt/netosis && git pull
bash /opt/netosis/scripts/soc-dashboard-setup.sh
bash /opt/netosis/scripts/lab-verify.sh          # role: soc
#   -> writes /root/netosis-node-keys.env (root 600): one key per honeypot

# --- copy that file to the Proxmox host as /root/netosis-node-keys.env (chmod 600)

# --- Proxmox host, as root -------------------------------------------------
#   CTs need Internet once, for apt + pip: allow it on OPNsense for the install
git clone https://github.com/aheedkhan/NetOsis.git /root/netosis   # or git pull
bash /root/netosis/scripts/lab-rollout.sh       # pushes code, installs, verifies CT102/104/105
#   now close the CTs' Internet access and apply the rules in section 4, then:
bash /root/netosis/scripts/lab-rollout.sh --verify-only
rm /root/netosis-node-keys.env                   # and on VM103 too
```

What `lab-rollout.sh` does for each CT:
1. Starts the CT if it is stopped.
2. Pushes the committed code (`git archive`) with `pct push`. No SSH, and no GitHub access needed inside the CT.
3. Runs `lab-bootstrap-remote.sh <profile> --key-stdin`. The key goes in on stdin, never on a command line.
4. That installs the venv, `netosis-ssh`, the agent and logrotate, and removes any old master token from the CT.
5. Runs `lab-verify.sh` inside the CT.
6. Prints a summary.

Updating later means the same command: `git pull` on the host, then `lab-rollout.sh`. `.env`, `.venv` and `data/` are kept.

## 4. Firewall rules (OPNsense, by hand)

Rules are evaluated top-down per interface; end each honeypot VLAN with a **block + log** rule.

| Interface | Action | Source | Destination | Port | Why |
|---|---|---|---|---|---|
| WAN | NAT | any | 192.168.30.10 | TCP 22 → 2222 | the only way in |
| ENT (30) | pass | 192.168.30.10 | 192.168.40.31 | TCP 8001 | telemetry + agent |
| ENT (30) | pass | 192.168.30.10 | 192.168.40.31 | TCP 11434 | LLM for unknown commands |
| ENT (30) | pass | 192.168.30.10 | 192.168.10.10, 192.168.20.10 | TCP 2222 | lateral-movement relay |
| FIN (10) | pass | 192.168.10.10 | 192.168.40.31 | TCP 8001, 11434 | telemetry, LLM |
| OPS (20) | pass | 192.168.20.10 | 192.168.40.31 | TCP 8001, 11434 | telemetry, LLM |
| ENT / FIN / OPS | **block, log** | that net | any | any | no Internet, no firewall GUI, no SOC dashboard, no real servers |
| SOC (40) | pass | 192.168.40.31 | Proxmox API | TCP 8006 | honeypot auto-wake (restricted token) |
| SOC (40) | pass | 192.168.40.31 | any | UDP 123 | NTP (signatures carry a timestamp) |
| SOC (40) | block, log | 192.168.40.31 | 192.168.10/20/30.0/24 | any | the controller never opens a connection to a honeypot |
| LAN (Jbox) | pass | 192.168.1.10 | 192.168.40.31 | TCP 8000 | the analyst's dashboard |

During the install window only, add a temporary `pass` from the CT to any on TCP 80/443 and UDP 53 above the block rule, then remove it.
Also tick `firewall=1` on CT105's NIC (`lab-rollout.sh` warns about it).

## 5. Where every log goes

| Where | What | How to read it | Kept |
|---|---|---|---|
| each CT | every attacker event (commands, risk, ATT&CK, deception), the source of truth | `/opt/netosis/data/telemetry.jsonl` | logrotate: weekly or 200 MB, 8 kept, gz |
| each CT | the attacker's profile and attack graph | `/opt/netosis/data/actor_profile.json`, `attack_graph.json`, `profiles/` | overwritten live |
| each CT | honeypot process (connects, LLM errors, ship errors, pivots) | `journalctl -u netosis-ssh -f` | journald: 300 MB / 30 days |
| each CT | agent (start-up, failed reports) | `journalctl -u netosis-agent -f` | journald |
| VM103 | everything received from all CTs | `/opt/netosis/data/soc/events.jsonl` (+ `state.json`) | logrotate, as above |
| VM103 | controller (wakes with requesting node, errors) | `journalctl -u netosis-controller -f` | journald |
| VM103 | refused / forged writes, who authenticates how | dashboard → System & policies → Node security | live (since start) |
| Proxmox host | CT start/stop from auto-wake | GUI → Tasks, or `/var/log/pve/tasks/` | Proxmox default |
| OPNsense | allowed / blocked flows (attacks, escapes) | Firewall → Log Files → Live View (log the block rules) | OPNsense default |

If the SOC is down, nothing is lost: each CT keeps its own `telemetry.jsonl`, and shipping resumes when the SOC is back. Events from the outage stay only on the CT.

## 6. Checks and maintenance

* `bash /opt/netosis/scripts/lab-verify.sh` runs on any node and changes nothing.
  * It reports: services up, the agent listening on nothing, file permissions, no master token on CTs, what each CT can and can't reach, and the fake-shell leak test.
  * **FAIL** means fix it first. **WARN** is a firewall rule or setting to look at.
* `bash /root/netosis/scripts/lab-rollout.sh --verify-only` runs those checks on all CTs from the host.
* **Rotate every key:**
  1. Put a new `NETOSIS_INGEST_TOKEN` in `controller/.env`.
  2. `systemctl restart netosis-controller`.
  3. `bash scripts/soc-dashboard-setup.sh` writes new node keys.
  4. Run `lab-rollout.sh` again.
* **Revoke one node:** remove it from `NETOSIS_NODES` and restart the controller.
* **Clock:** CTs use the Proxmox host's clock; VM103 must run NTP. More than 90 s of drift and its writes are refused (`lab-verify.sh` warns).
* **Before facing real attackers:** set `NETOSIS_LLM_DEMO_MARK=0` in each CT's `.env` (the `[llm]` mark is for demos).
