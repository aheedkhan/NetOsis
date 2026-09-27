# NetOsis — Adaptive AI Cyber Deception Platform

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-20%2F20%20passing-brightgreen.svg)](tests/)
[![Architecture](https://img.shields.io/badge/architecture-Proxmox%20SDN%20%7C%20OPNsense-navy.svg)](docs/network.md)

NetOsis is a production-grade, software-defined cyber deception system designed to trap, track, and confuse attackers inside virtualized enterprise environments. It combines a deterministic command engine, automated MITRE ATT&CK mapping, a risk-based adaptive policy ladder, local RAG (Retrieval-Augmented Generation), and local LLMs (Qwen 2.5) to deliver realistic terminal interactions without giving attackers a real shell.

---

## 📊 Current Project Status & Accomplishments

| Component / Feature | Description | Status |
| :--- | :--- | :--- |
| **Phase 0: Infrastructure & Network Model** | Proxmox SDN (`fypzone` VLAN zone, `FIN`/`OPS`/`ENT`/`SOC` VNets), OPNsense L3 gateways, Kea DHCP & IP plan. | ✅ **Complete & Documented** |
| **Phase 1: Deterministic Shell Engine** | Fast emulation for `pwd`, `whoami`, `ls`, `cat`, `cd`, `ps`, `ip addr`, `ip route`. | ✅ **Complete & Passing Tests** |
| **Phase 2: ATT&CK Mapping & Policy Ladder** | Real-time JSONL telemetry, graph builder, risk scoring, and deception triggers D01–D07. | ✅ **Complete & Passing Tests** |
| **Phase 3: Hybrid RAG + Local Qwen LLM** | MiniLM embeddings + local Qwen 2.5:3b via Ollama to hallucinate context-aware output for unknown commands. | ✅ **Complete & Passing Tests** |
| **SSH Honeypot Front-Door** | Multi-threaded Paramiko SSH server (`scripts/ssh_honeypot.py`) listening on port 2222. | ✅ **Complete & Active** |
| **Lab Deployment & Systemd Service** | Deployment scripts (`scripts/deploy_to_lab.sh`) & `netosis-ssh.service` unit for Proxmox server deployment. | ✅ **Ready for Deployment** |

---

## 🏗️ Server & Network Architecture

NetOsis operates within a multi-tiered Proxmox VE + OPNsense network architecture designed to isolate deception traps while keeping them visually indistinguishable from real employee systems.

```
+-----------------------------------------------------------------------------------+
| PROXMOX DATACENTER (Node: vhos)                                                   |
|                                                                                   |
|  [Datacenter > SDN > Zones]                                                       |
|   └── fypzone (Type: vlan, IPAM: pve)                                            |
|        │                                                                          |
|        ├── [Datacenter > SDN > VNets]                                             |
|        │    ├── FIN (VLAN Tag 10)  --> Finance Subnet (192.168.10.0/24)          |
|        │    ├── OPS (VLAN Tag 20)  --> Operations Subnet (192.168.20.0/24)       |
|        │    ├── ENT (VLAN Tag 30)  --> Enterprise Subnet (192.168.30.0/24)       |
|        │    └── SOC (VLAN Tag 40)  --> SOC / Monitoring (192.168.40.0/24)          |
|        │                                                                          |
|        └── [System > Network > Bridges]                                           |
|             ├── vmbr0 (Management & External WAN: 172.30.226.0/24, Non-VLAN-Aware) |
|             └── vmbr1 (Internal 802.1Q Trunk Bridge, VLAN-aware: YES)            |
|                                                                                   |
+--------------------------------------│--------------------------------------------+
                                       │ (802.1Q Tagged Trunk over vtnet0)
                                       v
+-----------------------------------------------------------------------------------+
| OPNSENSE FIREWALL & ROUTER (VM 101)                                              |
|                                                                                   |
|  [Interfaces: Assignments]                                                        |
|   ├── WAN: vtnet1 (172.30.226.X on vmbr0)                                        |
|   └── LAN: vtnet0 (Trunk Parent on vmbr1)                                         |
|        ├── opt2: FINANCE_VLAN10    (vlan0.10, Tag 10, GW: 192.168.10.254)         |
|        ├── opt3: OPERATIONS_VLAN20 (vlan0.20, Tag 20, GW: 192.168.20.254)         |
|        ├── opt4: ENTERPRISE_VLAN30 (vlan0.30, Tag 30, GW: 192.168.30.254)         |
|        └── opt5: SOC_VLAN40        (vlan0.40, Tag 40, GW: 192.168.40.254)         |
+-----------------------------------------------------------------------------------+
```

### 🔢 IP Allocation & Segmentation Policy
Within every `/24` VLAN subnet, IP addresses are strictly partitioned to maintain clean administration and microsegmentation:

* **`.1` to `.30`**: **Honeypots / Deception Decoys** (e.g. `192.168.30.10` ENT SSH Honeypot).
* **`.31` to `.253`**: **Real Employee VMs / Real Servers** (e.g. `192.168.10.31` FIN-USER-01).
* **`.254`**: **OPNsense Gateway**.

### 🏷️ Proxmox VM ID Numbering Scheme
* **100**: Management Jumpbox
* **101**: OPNsense Firewall
* **105 - 189**: Real Finance VMs (VLAN 10)
* **190 - 199**: Finance Honeypots (VLAN 10)
* **200 - 289**: Real Operations VMs (VLAN 20)
* **290 - 299**: Operations Honeypots (VLAN 20)
* **300 - 389**: Real Enterprise VMs & Jumpboxes (VLAN 30)
* **390 - 399**: Enterprise Honeypots (VLAN 30)
* **400 - 489**: Real SOC VMs (Wazuh, SIEM) (VLAN 40)
* **490 - 499**: NetOsis LLM Controllers (VLAN 40)

---

## 🚀 Quickstart & Server Deployment

### 1. Local Interactive CLI
```bash
# Clone and enter directory
git clone git@github.com:aheedkhan/NetOsis.git
cd NetOsis

# Create virtual environment and install dependencies
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Run vertical slice demo
python -m scripts.demo_vertical_slice
```

### 2. Run Live SSH Honeypot Server
```bash
source .venv/bin/activate
python scripts/ssh_honeypot.py --port 2222
```
*In another terminal, connect via SSH:*
```bash
ssh admin@127.0.0.1 -p 2222
```

### 3. Enable Qwen 2.5 Local LLM Fallback (CPU Optimized)
```bash
# Install Ollama and pull Qwen 2.5 3B model
ollama pull qwen2.5:3b

# Configure .env file
cp .env.example .env
# Ensure .env contains:
# NETOSIS_LLM_MODE=qwen
# NETOSIS_LLM_BASE_URL=http://127.0.0.1:11434/v1
# NETOSIS_LLM_MODEL=qwen2.5:3b

# Restart SSH Honeypot
python scripts/ssh_honeypot.py --port 2222
```

### 4. Deploy to Proxmox Server Host
To deploy NetOsis to a dedicated Proxmox VM/LXC container host:
```bash
# Using deployment script
./scripts/deploy_to_lab.sh
```
The script will push the project files, set up python virtual environments, and register the `netosis-ssh.service` systemd daemon.

---

## 🧪 Running Test Suite

```bash
source .venv/bin/activate
pytest
```
*Output:* `20 passed in 0.20s`

---

## 📚 Detailed Documentation
* [Lab Network & Proxmox SDN Guide](docs/network.md)
* [OPNsense & Kea DHCP Setup Guide](docs/OPNSENSE_SDN_GUIDE.md)
* [SSH Honeypot Proxy Details](docs/ssh-honeypot.md)
* [Local LLM Configuration Guide](docs/llm-local.md)
* [Word Report Document](NetOsis_Lab_Architecture_and_Setup_Guide.docx)
