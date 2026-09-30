# Corporate Network Topology (RAG / viva) — final FYP inventory

## No employee desktop VMs

Server-focused lab: honeypots (LXC) + real servers (VMs) + SOC. Saves RAM for Qwen/Wazuh.

## Jumpboxes

* **Management jumpbox** `172.30.227.1` — VPN/FreeRDP to Proxmox & OPNsense (not on FYP VLANs).
* **Enterprise jump / admin** `192.168.30.31` (`ENT-JUMP-01`) — manage real servers; **filtered from HHP**.

## Fake Internet (vmbr0)

* Kali `172.30.226.50` → OPNsense WAN `172.30.226.100`.
* NAT: WAN `:80` → real web `192.168.30.40`; WAN `:22` → WEB-HP `192.168.30.10:2222` (intentional loophole).

## VLAN inventory (static)

| Node | VLAN | IP | Form | Role |
|------|------|-----|------|------|
| FIN-HP-01 | 10 | `.10` | LXC HP | Finance decoy |
| FINANCE-DB-REAL-01 | 10 | `.50` | VM | Real backup/DB |
| OPS-HP-01 | 20 | `.10` | LXC HP | Ops decoy |
| OPS-APP-REAL-01 | 20 | `.50` | VM | Real ERP/ops |
| WEB-HP-01 / ent-web-01 | 30 | `.10` | LXC HP | Entry SSH honeypot |
| ENT-JUMP-01 | 30 | `.31` | VM | Admin SSH |
| ENT-WEB-REAL-01 | 30 | `.40` | VM | Public nginx |
| netosis-controller + Ollama | 40 | `.31` | VM | LLM/RAG/sandbox API |
| Wazuh (optional) | 40 | `.40` | VM | SIEM |

Gateways `.254`. DHCP `.100–.200` reserved (unused for these nodes).

## HHP egress

HPs may reach **SOC only**. Proxmox FW denies HHP → real `.31–.253` (same-VLAN L2 bypass mitigation).
