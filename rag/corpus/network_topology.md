# Corporate Network Topology (RAG / viva)

## Jumpboxes

* **Management jumpbox** `172.30.227.1` — VPN/FreeRDP to administer Proxmox & OPNsense. Not on VLAN 10/20/30.
* **Enterprise jumpbox** `192.168.30.31` — internal hop to manage enterprise servers on VLAN 30.

## Fake Internet (vmbr0)

* Subnet `172.30.226.0/24` simulates the public Internet.
* Kali attacks the OPNsense WAN address (lab public IP).
* NAT: WAN `:80` → real web `192.168.30.40`; WAN `:22` → honeypot `192.168.30.10:2222`.

## VLAN Segments

* **VLAN 10 Finance** `192.168.10.0/24` gw `.254` — employees (`.31+`) + Finance HHPs (`.1–.30`).
* **VLAN 20 Operations** `192.168.20.0/24` gw `.254` — employees + Ops HHPs.
* **VLAN 30 Enterprise** `192.168.30.0/24` gw `.254` — **no employees**; ENT jump, real servers, Enterprise HHP (`ent-web-01` = `192.168.30.10`).
* **VLAN 40 SOC** `192.168.40.0/24` gw `.254` — NetOsis controller, LLM/Ollama, Wazuh.
* **Management** `172.30.226.0/24` — restricted hypervisor/WAN lab fabric.

## IP policy

* `.1`–`.30` honeypots · `.31`–`.253` reals · `.254` gateway

## Routing

Inter-VLAN via OPNsense. Same-VLAN HHP isolation via Proxmox firewall (default-deny out from HHP LXCs).
