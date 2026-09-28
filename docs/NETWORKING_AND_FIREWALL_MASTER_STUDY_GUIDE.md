# NetOsis Master Networking & Firewall Study Guide

## 📚 Table of Contents
1. [Core Concepts: Layer 2 vs. Layer 3](#1-core-concepts-layer-2-vs-layer-3)
2. [Proxmox SDN Architecture (`fypzone`, VNets & Bridges)](#2-proxmox-sdn-architecture)
3. [OPNsense Routing, Gateways & Interface Mapping](#3-opnsense-routing-gateways--interface-mapping)
4. [DHCP Architecture & IP Partitioning Strategy](#4-dhcp-architecture--ip-partitioning-strategy)
5. [End-to-End Packet Walks (Complete Packet Traces)](#5-end-to-end-packet-walks)
6. [Cyber Deception Isolation & Microsegmentation](#6-cyber-deception-isolation--microsegmentation)
7. [Self-Study Commands & Diagnostic Checklist](#7-self-study-commands--diagnostic-checklist)

---

## 1. Core Concepts: Layer 2 vs. Layer 3

To understand how NetOsis routes traffic, you must understand the distinction between **Layer 2 (Data Link)** and **Layer 3 (Network)**:

```
+-----------------------------------------------------------------------------------+
| LAYER 3 (Network Layer - IP Addresses & Routing)                                  |
| • Operates via IP addresses (192.168.10.100, 8.8.8.8)                             |
| • Handled by OPNsense Router/Firewall                                             |
| • Decisions based on Routing Tables & Firewall Policies                            |
+-----------------------------------------------------------------------------------+
                                        ▲
                                        │ (Decapsulation / Encapsulation)
                                        ▼
+-----------------------------------------------------------------------------------+
| LAYER 2 (Data Link Layer - MAC Addresses & 802.1Q VLAN Tags)                      |
| • Operates via MAC addresses (bc:24:11:30:4e:dd) and 802.1Q Tags (10, 20, 30, 40) |
| • Handled by Proxmox Linux Bridges (vmbr0, vmbr1) & Virtual Switches (VNets)       |
| • Isolates broadcast domains so VLAN 10 frames cannot reach VLAN 30 without L3   |
+-----------------------------------------------------------------------------------+
```

### 802.1Q VLAN Tagging
A **VLAN (Virtual Local Area Network)** allows multiple virtual networks to share a single physical bridge or cable. An 802.1Q header inserts a 4-byte "Tag" into the Ethernet frame:
* **Untagged Frame**: A plain Ethernet frame without a VLAN ID.
* **Tagged Frame**: Contains a VLAN ID (e.g., `Tag 10` for Finance, `Tag 20` for Ops, `Tag 30` for Enterprise, `Tag 40` for SOC, `Tag 226` for WAN, `Tag 227` for VPN Jumpbox).

---

## 2. Proxmox SDN Architecture

Proxmox Software-Defined Networking (SDN) abstracts complex hypervisor bridges into clean virtual objects:

```
PROXMOX DATACENTER (Node: vhos)
 └── SDN Zone: fypzone (Type: vlan, IPAM: pve)
      │
      ├── VNets (Virtual Networks)
      │    ├── FIN  --> VLAN Tag 10 (Finance: 192.168.10.0/24)
      │    ├── OPS  --> VLAN Tag 20 (Operations: 192.168.20.0/24)
      │    ├── ENT  --> VLAN Tag 30 (Enterprise: 192.168.30.0/24)
      │    └── SOC  --> VLAN Tag 40 (SOC: 192.168.40.0/24)
      │
      └── Underlying Linux Bridges
           ├── vmbr0: Non-VLAN-aware (Management / External WAN: 172.30.226.0/24)
           │    ├── Tag 226: OPNsense WAN Interface (vtnet1)
           │    └── Tag 227: Jumpbox Management NIC (VM 100 net0 -> 172.30.227.1)
           │
           └── vmbr1: VLAN-aware Trunk Bridge (Carries Tags 10, 20, 30, 40)
                └── OPNsense LAN Parent Interface (vtnet0 / VM 101 net0)
```

### Why Proxmox requires the "Apply" button:
When you add or modify a VNet under `fypzone`, Proxmox writes the configuration to `/etc/pve/sdn/`. Clicking **Datacenter > SDN > Apply** generates the underlying `ebtables` and `bridge vlan` commands on node `vhos` to allow frames with those tags to flow across `vmbr1`.

---

## 3. OPNsense Routing, Gateways & Interface Mapping

OPNsense acts as the default gateway (`.254`) for all internal subnets and the NAT translator for WAN traffic.

### Interface Mapping Table:
| OPNsense Identifier | Description | Parent Device | VLAN Tag | Subnet | Gateway IP |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`wan`** | WAN (External) | `vtnet1` (hardware) | `226` | `172.30.226.0/24` | `172.30.226.100` |
| **`lan`** | LAN Trunk Parent | `vtnet0` (hardware) | Trunk | N/A | N/A |
| **`opt2`** | `FINANCE_VLAN10` | `vlan0.10` | `10` | `192.168.10.0/24` | `192.168.10.254` |
| **`opt3`** | `OPERATIONS_VLAN20` | `vlan0.20` | `20` | `192.168.20.0/24` | `192.168.20.254` |
| **`opt4`** | `ENTERPRISE_VLAN30` | `vlan0.30` | `30` | `192.168.30.0/24` | `192.168.30.254` |
| **`opt5`** | `SOC_VLAN40` | `vlan0.40` | `40` | `192.168.40.0/24` | `192.168.40.254` |

### Default Gateways:
* **`WAN_GW`**: IP **`172.30.226.254`** on `vmbr0`. This is the upstream physical router that connects OPNsense to the internet.

---

## 4. DHCP Architecture & IP Partitioning Strategy

To combine dynamic employee provisioning with static honeypot tracking, every `/24` subnet (`192.168.x.0/24`) is strictly partitioned into 4 distinct IP blocks:

```
192.168.x.0/24 Subnet Layout:
┌─────────────────────────┬─────────────────────────┬─────────────────────────┬────────────┐
│ .1  to  .30             │ .31  to  .99            │ .100  to  .200          │ .254       │
│ HONEYPOTS & DECOYS      │ REAL INFRASTRUCTURE     │ DYNAMIC DHCP POOL       │ GATEWAY    │
│ (Static IPs Only)       │ (Static IPs Only)       │ (Dnsmasq / Kea DHCP)    │ (OPNsense) │
└─────────────────────────┴─────────────────────────┴─────────────────────────┴────────────┘
```

1. **`.1` to `.30` (Honeypots / Decoys - STATIC)**:
   * **Purpose**: NetOsis SSH & Web Honeypot containers (e.g. `192.168.30.10`).
   * **Why Static?**: Honeypots must never change IP addresses so that RAG vector search, attack graphs, and MITRE ATT&CK telemetry remain consistent.
2. **`.31` to `.99` (Real Infrastructure - STATIC)**:
   * **Purpose**: Permanent servers (e.g. Real Web Server `192.168.30.31`).
3. **`.100` to `.200` (Dynamic DHCP Pool - AUTOMATED)**:
   * **Purpose**: Real Employee VMs (`VM 102`, `FIN-USER-01`, `OPS-USER-01`) and test templates.
   * **Why DHCP?**: When you spin up employee VMs from a Proxmox template, Dnsmasq automatically assigns them an IP, Gateway (`.254`), and DNS (`8.8.8.8`) in 2 seconds without manual intervention.
4. **`.254` (Default Gateway)**: OPNsense L3 router interface.

---

## 5. End-to-End Packet Walks

### 🛰️ Trace 1: DNS Resolution & Outbound Internet Access (VM 102 -> Internet)

Scenario: **VM 102** (attached to VNet `SOC` / VLAN Tag 40, IP `192.168.40.100`) runs `ping google.com` or `apt update`.

```
[ VM 102 (Ubuntu Template) ]
  IP: 192.168.40.100 | GW: 192.168.40.254 | DNS: 8.8.8.8
         │
         │ 1. VM 102 sends UDP DNS query: "What is the IP of google.com?" (to 8.8.8.8)
         │    VNet "SOC" inserts 802.1Q Header with VLAN Tag 40 into the Ethernet frame.
         v
[ Proxmox Linux Bridge vmbr1 ]
         │
         │ 2. The frame tagged with VLAN 40 travels across vmbr1.
         v
[ OPNsense LAN NIC (vtnet0) ]
         │
         │ 3. vtnet0 receives the frame, reads Tag 40, strips the tag, and delivers
         │    the raw packet to subinterface vlan0.40 (192.168.40.254).
         v
[ OPNsense Firewall & Routing Engine ]
         │
         │ 4. FIREWALL RULE CHECK: Evaluates SOC_VLAN40 rules -> Matches "Pass IPv4 any to any".
         │ 5. ROUTE LOOKUP: Destination 8.8.8.8 is NOT in local routing table -> Selects Default Gateway (WAN_GW: 172.30.226.254).
         │ 6. OUTBOUND NAT: Translates Source IP 192.168.40.100 to OPNsense WAN IP (172.30.226.100).
         v
[ OPNsense WAN NIC (vtnet1) ]
         │
         │ 7. Packet exits vtnet1 onto vmbr0 (tagged with VLAN Tag 226).
         v
[ Proxmox Linux Bridge vmbr0 (Tag 226) ]
         │
         │ 8. Forwarded to Upstream Lab Router (172.30.226.254).
         v
[ Public Internet (Google DNS 8.8.8.8) ]
         │
         │ 9. Google DNS replies with IP (142.250.190.46).
         │    Reply packet travels BACK through vmbr0 -> OPNsense WAN -> NAT Un-translation
         │    -> Delivered back over vmbr1 (Tag 40) -> VM 102!
```

---

### 🎯 Trace 2: Inbound Attack & NAT Port Forwarding (Kali -> Honeypot)

Scenario: Attacker on **Kali Linux** (`172.30.226.50` on `vmbr0`) runs `ssh admin@172.30.226.100 -p 2222`.

```
[ Kali Attacker (172.30.226.50) ]
         │
         │ 1. Sends TCP SYN packet to OPNsense WAN IP (172.30.226.100:2222) over vmbr0 (Tag 226).
         v
[ OPNsense WAN NIC (vtnet1) ]
         │
         │ 2. INBOUND NAT PORT FORWARDING: Matches rule "WAN :2222 -> 192.168.30.10:2222".
         │    Rewrites Destination IP to 192.168.30.10 (Enterprise Honeypot on VLAN 30).
         │ 3. FIREWALL PASS: WAN firewall rule allows port 2222 inbound.
         │ 4. ROUTE LOOKUP: Destination 192.168.30.10 is connected to subinterface vlan0.30.
         v
[ OPNsense vtnet0 (vlan0.30) ]
         │
         │ 5. Inserts 802.1Q Header with VLAN Tag 30 and pushes packet out vtnet0.
         v
[ Proxmox Linux Bridge vmbr1 ]
         │
         │ 6. Carries VLAN Tag 30 frame directly to Honeypot LXC container (VMID 390).
         v
[ NetOsis SSH Honeypot (192.168.30.10:2222) ]
         │
         │ 7. Paramiko SSH Server accepts connection, prompts for credentials,
         │    and starts capturing attacker commands into telemetry.jsonl!
```

---

## 6. Cyber Deception Isolation & Microsegmentation

Same VLAN ≠ Same Trust. Because Honeypots (`.1-.30`) sit in the same VLAN broadcast domains as real employee systems (`.31-.253`), Layer 3 (OPNsense) cannot filter direct Layer 2 ARP/MAC communication inside the same subnet.

To protect real employee systems from a compromised honeypot container:

```
+-----------------------------------------------------------------------------------+
| HYPERVISOR MICROSEGMENTATION (Proxmox Firewall: firewall=1)                       |
|                                                                                   |
|  [Honeypot LXC 390 (192.168.30.10)]                                              |
|   ├── ALLOW IN: TCP 2222 / 80 from OPNsense WAN                                  |
|   ├── ALLOW OUT: TCP 443 / 11434 to SOC VLAN 40 (NetOsis Controller & Qwen LLM)   |
|   └── DROP ALL OUTBOUND: To 192.168.10.0/24, 20.0/24, 30.0/24 (.31-.253)          |
|       (Drops same-subnet lateral pivots at the hypervisor bridge level!)          |
+-----------------------------------------------------------------------------------+
```

---

## 7. Self-Study Commands & Diagnostic Checklist

Use these shell commands to verify and inspect your network at every layer:

### On Proxmox Host (`vhos`):
```bash
# View all Linux bridges and VLAN-aware status
ip link show

# Inspect VLAN tags active on bridge vmbr1
bridge vlan show

# View active SDN VNets and zones
cat /etc/pve/sdn/vnets.cfg
cat /etc/pve/sdn/zones.cfg
```

### On OPNsense Firewall (via SSH or Web Diagnostics):
```bash
# Check interface IP addresses and VLAN subinterfaces
ifconfig

# Test ping from OPNsense WAN out to internet
ping -c 4 8.8.8.8

# View active NAT translations
pfctl -s nat
```

### On Ubuntu Template VM (VM 102):
```bash
# Inspect IP address received from Dnsmasq
ip a

# Inspect routing table and default gateway (.254)
ip r

# Test DNS resolution
resolvectl status
ping -c 4 google.com
```
