# OPNsense, Proxmox SDN, and Lab Architecture Master Guide

Synced with screenshots / Excel plan. Machine truth: [`config/network/vlans.yml`](../config/network/vlans.yml).

## 1. Proxmox SDN architecture

| Layer | Name | Role |
|-------|------|------|
| SDN Zone | `fypzone` (type **vlan**, IPAM **pve**, node **vhos**) | 802.1Q over `vmbr1` |
| VNets | `FIN` / `OPS` / `ENT` / `SOC` | Tags **10 / 20 / 30 / 40** |
| Bridge | `vmbr1` | VLAN-aware trunk to OPNsense LAN (`vtnet0`) |
| Bridge | `vmbr0` | Non-VLAN-aware fake Internet / mgmt `172.30.226.0/24` |

**vmbr0 hosts (examples):** Proxmox `172.30.226.7`, Kali `172.30.226.50`, OPNsense WAN `vtnet1` (e.g. `172.30.226.100`).  
**Management jumpbox** `172.30.227.1` is admin VPN/RDP (not Enterprise jumpbox; keep off attacker paths).

Attaching a VM NIC to VNet **FIN** auto-tags VLAN **10** (same idea for OPS/ENT/SOC).

## 2. OPNsense interfaces (from lab evidence)

| Assignment | Interface | Addressing |
|------------|-----------|------------|
| WAN | `vtnet1` on `vmbr0` | `172.30.226.x/24` |
| LAN parent | `vtnet0` on `vmbr1` | trunk parent |
| opt2 FINANCE_VLAN10 | `vlan0.10` tag 10 | `192.168.10.254/24` |
| opt3 OPERATIONS_VLAN20 | `vlan0.20` tag 20 | `192.168.20.254/24` |
| opt4 ENTERPRISE_VLAN30 | `vlan0.30` tag 30 | `192.168.30.254/24` |
| opt5 SOC_VLAN40 | `vlan0.40` tag 40 | `192.168.40.254/24` |

## 3. Traffic flows

### A) Employee → Internet (e.g. VM 102 on FIN)

1. Host uses GW `.254` on its VLAN  
2. Tagged on `vmbr1` → OPNsense VLAN subiface  
3. Firewall allow → Outbound NAT on WAN → `vmbr0` → upstream `172.30.226.254`

### B) Kali → “public” WAN → HHP (external story)

1. Kali on `vmbr0` scans OPNsense WAN IP  
2. NAT: WAN `:80` → real web `192.168.30.40`; WAN `:22` → HHP `192.168.30.10:2222`  
3. Egress on `vlan0.30` / tag 30 → CT/VM **390**

### C) IP blocks + isolation

| Range | Use |
|-------|-----|
| `.1`–`.30` | Honeypots |
| `.31`–`.253` | Real systems |
| `.254` | Gateway |
| DHCP pools | `.100`–`.200` (leaves static `.31`–`.99`) |

**HHP outbound policy (correct for NetOsis):**

- **Block** HHP (`.1–.30`) → real ranges (`.31–.253`) on same/other user VLANs  
- **Allow** HHP → **SOC `192.168.40.0/24`** only as needed (Ollama / controller / telemetry)  
- Do **not** blanket-block all of VLAN 40 or the LLM path breaks  

Use OPNsense rules **and** Proxmox FW (`firewall=1`) on HHP LXCs.

## 4. Why you don’t see “DHCPv4” (OPNsense 24.x)

Legacy **Services → DHCPv4** (ISC) was removed/replaced.

Use one of:

| Menu | When |
|------|------|
| **Services → Kea DHCP** | Default modern DHCP (recommended) |
| **Services → Dnsmasq DNS & DHCP** | If you chose Dnsmasq for DHCP instead |

Also use **Services → Unbound DNS** for resolver (separate from DHCP).

### Kea DHCP — configure each VLAN

1. **Services → Kea DHCP → Settings** — enable Kea  
2. **Subnets → +** for each VLAN:

| Subnet | Pool | Routers | DNS |
|--------|------|---------|-----|
| `192.168.10.0/24` | `192.168.10.100`–`200` | `192.168.10.254` | `8.8.8.8` or `.254` |
| `192.168.20.0/24` | `192.168.20.100`–`200` | `192.168.20.254` | same pattern |
| `192.168.30.0/24` | `192.168.30.100`–`200` | `192.168.30.254` | same |
| `192.168.40.0/24` | `192.168.40.100`–`200` | `192.168.40.254` | same |

3. Bind/enable the subnet on the matching interface (FINANCE_VLAN10, etc.)  
4. **Apply**  
5. On VM 102 (VNet FIN): DHCP or static; test `ping 192.168.10.254`, `ping 8.8.8.8`, `ping google.com`

If Kea UI shows subnets but leases never appear: confirm the VLAN interface is **up**, has `.254/24`, and firewall allows UDP **67/68** to the firewall on that VLAN.

## 5. Execution sequence

1. Verify SDN (`fypzone`, VNets, `vmbr1` VLAN-aware)  
2. OPNsense VLAN IPs `.254`  
3. **Kea DHCP** pools + Unbound/DNS  
4. Outbound NAT + firewall (Internet pass; HHP block to reals; HHP allow SOC)  
5. VM 102 template connectivity  
6. HHP LXC 390 + Proxmox FW + optional WAN NAT ([`ops/opnsense/PROPOSED_WAN_NAT.md`](../ops/opnsense/PROPOSED_WAN_NAT.md))

## 6. Artifacts

- Excel: `NetOsis_NETWORK_PLAN_UPDATED.xlsx`  
- Docx (screenshots): `NetOsis_Lab_Architecture_and_Setup_Guide.docx` (if present in workspace)  
- This guide: `docs/OPNSENSE_SDN_GUIDE.md`
