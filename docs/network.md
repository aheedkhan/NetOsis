# NetOsis Lab Network Architecture (locked)

Authoritative machine config: [`config/network/vlans.yml`](../config/network/vlans.yml).

## 1. Proxmox bridges

| Bridge | Role |
|--------|------|
| **`vmbr0`** | Management / **fake Internet** — `172.30.226.0/24`. Proxmox host, OPNsense **WAN**, Kali attacker. Never expose real WAN. |
| **`vmbr1`** | VLAN-aware FYP trunk → OPNsense LAN / VLANs 10,20,30,40 |

**Management jumpbox** `172.30.227.1` is the VPN/FreeRDP admin box (not on FYP VLANs; not the Enterprise jumpbox). Keep it off attacker paths.

## 2. IP policy (every FYP `/24`)

| Range | Use |
|-------|-----|
| `.1`–`.30` | Honeypots (HHP) |
| `.31`–`.253` | Real employees / servers / enterprise jumpbox |
| `.254` | OPNsense gateway |

## 3. VLAN roles

| VLAN | Contents |
|------|----------|
| **10 Finance** | Employees (`.31+`) + Finance HHP (`.1–.30`) |
| **20 Operations** | Employees (`.31+`) + Ops HHP |
| **30 Enterprise** | **No employees** — ENT jumpbox, real servers, Enterprise HHP |
| **40 SOC** | NetOsis controller, Ollama/LLM, Wazuh |

Key IPs:

- HHP `ent-web-01` → `192.168.30.10` (VMID hint **390**)
- Real web → `192.168.30.40`
- Enterprise jumpbox → `192.168.30.31` (manage servers — **not** `172.30.227.1`)
- Finance HHP → `192.168.10.10`

## 4. VMID blocks (suggested)

| IDs | Role |
|-----|------|
| 101 | OPNsense |
| 105–189 / 190–199 | Real FIN / FIN HHP |
| 200–289 / 290–299 | Real OPS / OPS HHP |
| 300–389 / 390–399 | Real ENT (+ jump) / ENT HHP |
| 400–489 / 490–499 | SOC services / NetOsis controller |

Employees = **linked clones** from golden template. HHPs = separate **LXC** (not from employee template).

## 5. External attack path (no real public IP)

```text
Kali on vmbr0  (e.g. 172.30.226.50)
  → scans OPNsense WAN (lab "public IP", e.g. 172.30.226.100)
  → OPNsense NAT / port forward
       :80  → real ENT web  192.168.30.40
       :22  → HHP           192.168.30.10:2222
```

See proposed NAT checklist: [`ops/opnsense/PROPOSED_WAN_NAT.md`](../ops/opnsense/PROPOSED_WAN_NAT.md).  
**Do not apply** until you approve — no automatic OPNsense changes.

## 6. Isolation

- **L3 between VLANs:** OPNsense ACLs + logs (viva-friendly lateral movement).
- **Same VLAN (FIN/OPS HHP vs employees):** Proxmox firewall on HHP LXC — default-deny outbound; allow SOC (`192.168.40.0/24`) only if needed for LLM/telemetry.
- HHP process is a fake shell; FW still protects against LXC escape.

## 7. Template / employee Internet

Guest DNS/gateway issues: test `ping 1.1.1.1` vs `ping google.com`.  
DHCP: use **Kea DHCP** on OPNsense 24.x — see [`OPNSENSE_SDN_GUIDE.md`](OPNSENSE_SDN_GUIDE.md) (no legacy DHCPv4 menu).
