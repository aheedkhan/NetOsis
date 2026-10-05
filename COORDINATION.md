# NetOsis — Shared Multi-Agent Coordination & Execution Log

> **Purpose**: Single source of truth for **Antigravity (AGY)**, **Cursor**, and the **User** to track state, avoid conflicts, and execute tasks across tabs.

---

## 📌 Active Agent State

| Tab / Agent | Current Assignment | Active Files / Scope | Status |
| :--- | :--- | :--- | :--- |
| **Tab 1: Antigravity (AGY)** | Network architecture alignment, container deployment specs, coordination tracking | `COORDINATION.md`, deployment planning, security trade-offs | 🟢 Active |
| **Tab 2: Cursor / AGY** | Local code development / honeypot runtime / RAG pipeline | `deception/`, `rag/`, `scripts/` | 🟢 Active |
| **User (Manual Execution)** | Running VPN, Proxmox GUI/CLI operations, container provisioning | Proxmox VE (`172.30.226.7`), OPNsense | 🟡 In Progress |

---

## 🌐 Network Mapping & Static IP Allocation (Segmented Architecture — NO DMZ)

* Architecture is **strictly segmented** into VLANs using Proxmox SDN (`fypzone` on `vmbr1`) and OPNsense gateways (`.254`).
* Honeypot range: `.1` – `.30` (LXC containers).
* Real infrastructure range: `.31` – `.99` (VMs).
* Microsegmentation rule: L2 firewall denies Honeypot (`.10`) access to local real servers (`.50`/`.40`), allowing only outbound traffic to SOC (`192.168.40.31`).

| VLAN Tag | Subnet | Gateway | Node Name | VMID | IP Address | Type | Role / Function |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **VLAN 10** | `192.168.10.0/24` | `192.168.10.254` | `finance-db-01` | **190** | `192.168.10.10` | LXC | Finance Honeypot (Postgres decoy) |
| **VLAN 10** | `192.168.10.0/24` | `192.168.10.254` | `FINANCE-DB-REAL-01` | **110** | `192.168.10.50` | VM | Real Finance DB Server |
| **VLAN 20** | `192.168.20.0/24` | `192.168.20.254` | `ops-app-01` | **290** | `192.168.20.10` | LXC | Operations Honeypot (ERP decoy) |
| **VLAN 20** | `192.168.20.0/24` | `192.168.20.254` | `OPS-APP-REAL-01` | **210** | `192.168.20.50` | VM | Real Operations ERP Server |
| **VLAN 30** | `192.168.30.0/24` | `192.168.30.254` | `ent-web-01` | **390** | `192.168.30.10` | LXC | **Enterprise SSH Honeypot (Port 2222)** |
| **VLAN 30** | `192.168.30.0/24` | `192.168.30.254` | `ENT-WEB-REAL-01` | **310** | `192.168.30.40` | VM | Real Enterprise Web Server (Port 80) |
| **VLAN 30** | `192.168.30.0/24` | `192.168.30.254` | `ENT-JUMP-01` | **300** | `192.168.30.31` | VM | Admin Jumpbox (internal admin) |
| **VLAN 40** | `192.168.40.0/24` | `192.168.40.254` | `netosis-soc` | **490** | `192.168.40.31` | VM/LXC | **Ollama LLM (Qwen 2.5:3b) + Telemetry Hub** |

---

## 🔒 Security Analysis: Pros, Cons & Compromise Boundaries

### What Can Be Compromised
1. **LXC Container Environment (`ent-web-01` - 390)**:
   * Attackers entering SSH `:22` get routed to honeypot `:2222`.
   * They only access the NetOsis emulated fake shell or sandboxed space.
   * If container breakout occurs on LXC, they compromise only the unprivileged container.
2. **Deception Lore & Synthetic Credentials**:
   * Attackers can find fake credentials (e.g., `fake_accounts_and_backups.md`). These credentials do NOT exist on the real `.50` servers.

### What CANNOT Be Compromised (Protected Boundary)
1. **Real Internal Production Servers (`.50` / `.40`)**:
   * Protected by Proxmox host-level firewall on the honeypot virtual NICs (drop all L2 traffic destined to `.31`–`.99` within same VLAN).
2. **Proxmox Management Plane & OPNsense Admin**:
   * Isolated on `vmbr0` / `172.30.226.0/24` and jumpbox `172.30.227.1`. No routes exist from honeypot VLANs to management.
3. **Core LLM Controller (VLAN 40)**:
   * Only inbound port `11434` (or `:8000`) is accessible from Honeypot to SOC; no reverse shell or SSH back into SOC allowed.

---

## 📋 Step-by-Step Execution Plan

- [ ] **Step 1: Start VPN & Verify Access**
  * Run `cd ~/Documents/server && ./start.sh`
  * Verify ping / SSH to Proxmox: `ping 172.30.226.7`
- [ ] **Step 2: Create Honeypot Containers on Proxmox**
  * SSH into Proxmox node `172.30.226.7`.
  * Create 3 LXC containers: VMID 190 (VLAN 10), VMID 290 (VLAN 20), VMID 390 (VLAN 30).
  * Set static IPs (`.10.10`, `.20.10`, `.30.10`) with gateway `.254`.
- [ ] **Step 3: Setup SOC Host (VMID 490 - `192.168.40.31`) & Deploy Local LLM**
  * Provision Ubuntu 22.04 on VLAN 40 (`192.168.40.31`).
  * Install Ollama: `curl -fsSL https://ollama.com/install.sh | sh`.
  * Pull model: `ollama pull qwen2.5:3b`.
  * Expose Ollama on `0.0.0.0:11434` (`OLLAMA_HOST=0.0.0.0:11434`).
- [ ] **Step 4: Deploy NetOsis Stack onto Enterprise Honeypot (390)**
  * Push repo files to `192.168.30.10:/opt/netosis`.
  * Configure `/opt/netosis/.env` to point to SOC Ollama (`http://192.168.40.31:11434/v1`).
  * Start and enable systemd service `netosis-ssh.service`.
- [ ] **Step 5: Apply Proxmox Firewall Isolation Matrix**
  * On LXC 390/290/190 firewall options: enable firewall.
  * Add OUT rule: Allow destination `192.168.40.31:11434` (SOC LLM).
  * Add OUT rule: Drop destination `192.168.0.0/16` (blocks lateral movement to real servers).
- [ ] **Step 6: Update Excel Tracking Sheet**
  * Record deployed VMIDs, MAC addresses, IP assignments, and status in `NetOsis_NETWORK_PLAN_UPDATED.xlsx`.

---

## 📝 Activity & Change Log (All Agents Update Here)

| Timestamp | By | Action Taken | Next Immediate Action |
| :--- | :--- | :--- | :--- |
| `2026-10-01 13:51` | Antigravity | Created `COORDINATION.md` with full static IP matrix, containment boundaries, and step plan | User executes Step 1 (VPN) & Step 2 (Proxmox LXCs) |
