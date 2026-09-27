# OPNsense, Proxmox SDN, and Lab Architecture Master Guide

## 1. Proxmox SDN Architecture & VLAN Mapping
* **Zone**: `fypzone` (Type: `vlan`, IPAM: `pve`, Node: `vhos`).
* **Trunk Bridge**: `vmbr1` (VLAN-aware: `Yes`).
* **Virtual Networks (VNets)**:
  * `FIN` -> VLAN Tag 10 -> Subnet `192.168.10.0/24`, Gateway `192.168.10.254`
  * `OPS` -> VLAN Tag 20 -> Subnet `192.168.20.0/24`, Gateway `192.168.20.254`
  * `ENT` -> VLAN Tag 30 -> Subnet `192.168.30.0/24`, Gateway `192.168.30.254`
  * `SOC` -> VLAN Tag 40 -> Subnet `192.168.40.0/24`, Gateway `192.168.40.254`
* **Management & WAN Bridge**: `vmbr0` (Non-VLAN-aware, `172.30.226.0/24`). Contains Proxmox host (`172.30.226.7`), Jumpbox (`172.30.227.1`), Kali Linux Attacker VM (`172.30.226.50`), and OPNsense WAN interface (`vtnet1`).

## 2. In-and-Out Traffic Flow
1. **Outbound Internet (VM 102 / Employees -> Internet)**:
   * VM 102 (`192.168.10.102` on VNet `FIN`) sends packet to `8.8.8.8` via gateway `192.168.10.254`.
   * Frame egresses `vmbr1` tagged with VLAN 10.
   * OPNsense receives packet on parent `vtnet0` subinterface `vlan0.10` (`FINANCE_VLAN10`).
   * OPNsense checks Firewall Rules for `FINANCE_VLAN10`. If allowed, packet is routed to WAN (`vtnet1`).
   * Outbound NAT translates source IP `192.168.10.102` -> WAN IP `172.30.226.X`.
   * Packet exits `vtnet1` onto `vmbr0` -> Upstream Gateway `172.30.226.254` -> Internet.

2. **Inbound Recon & Attack (Kali -> Honeypot)**:
   * Kali on `vmbr0` (`172.30.226.50`) targets OPNsense WAN IP (`172.30.226.X`) on Port 2222 or 80.
   * OPNsense WAN matches NAT Port Forwarding rule -> rewrites destination IP to Honeypot IP `192.168.30.10` (VLAN 30).
   * OPNsense WAN firewall rule passes packet out subinterface `vlan0.30` (`ENTERPRISE_VLAN30`) over `vmbr1` (Tag 30) -> Honeypot container/VM (`390`).

3. **Inter-VLAN & Deception Isolation**:
   * **IP Allocation Rule**:
     * `.1` to `.30`: Honeypots / Deception Decoys (e.g. `192.168.30.10` ENT Web Honeypot).
     * `.31` to `.253`: Real Employee VMs / Real Servers (e.g. `192.168.10.31` FIN-USER-01).
     * `.254`: OPNsense Gateway.
   * **Segmentation**: OPNsense rules + Proxmox Hypervisor Firewall (`firewall=1`) drop all outbound connections initiated by Honeypots (`.1-.30`) toward Real Employee IPs (`.31-.253`) or SOC VLAN 40.

## 3. Master Sequence of Execution
1. **Step 1: Proxmox SDN Verification**: Confirm `vmbr1` is VLAN-aware and `fypzone` has VNets `FIN`, `OPS`, `ENT`, `SOC` (Tags 10, 20, 30, 40).
2. **Step 2: OPNsense Interface Assignments**: Assign `vtnet1` to WAN, `vtnet0` to LAN, and assign subinterfaces `vlan0.10` (FINANCE_VLAN10), `vlan0.20` (OPERATIONS_VLAN20), `vlan0.30` (ENTERPRISE_VLAN30), `vlan0.40` (SOC_VLAN40). Set IPv4 address `.254/24` on each.
3. **Step 3: DHCP & DNS Configuration**:
   * OPNsense 24.x uses **Kea DHCP** (or **Dnsmasq**) under `Services > Kea DHCP`.
   * Add subnet definitions (e.g. `192.168.10.0/24`) and pools (`192.168.10.100` - `192.168.10.200`), Gateway `192.168.x.254`, DNS `8.8.8.8` / `192.168.x.254`.
4. **Step 4: OPNsense Outbound NAT & Firewall Rules**:
   * Enable Hybrid/Automatic Outbound NAT for `192.168.0.0/16` on WAN interface.
   * Create Pass rules on each VLAN interface for Internet access.
   * Create Block rules restricting Honeypot initiated traffic to real subnets.
5. **Step 5: VM 102 (Ubuntu Base) Configuration**:
   * Attach VM 102 NIC to VNet `FIN` (Tag 10).
   * Configure Netplan for DHCP or static IP `192.168.10.102/24`, gateway `192.168.10.254`, DNS `8.8.8.8`.
   * Verify with: `ping 192.168.10.254`, `ping 8.8.8.8`, `ping google.com`.
