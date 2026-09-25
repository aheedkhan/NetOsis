# NetOsis Lab Network Architecture

## 1. Proxmox Bridges
* **`vmbr0` (Management / Fake Internet):** `172.30.226.0/24`
  * Hosts the Management VPN Jumpbox (`172.30.227.1`).
  * Hosts the OPNsense WAN Interface (Acting as the Corporate Public IP).
  * Hosts the Kali Linux Attacker VM.
* **`vmbr1` (VLAN Trunk):** Connects OPNsense LAN to all internal subnets.

## 2. IP Addressing & Segmentation Rule
Within every `/24` VLAN, the IPs are strictly segmented by purpose:
* **`.1` to `.30`:** Honeypots (HHPs)
* **`.31` to `.253`:** Real Servers / Real Employees / Jumpboxes
* **`.254`:** OPNsense Gateway

## 3. Proxmox VM ID Scheme
* **100:** Management Jumpbox
* **101:** OPNsense Firewall
* **105 - 189:** Real Finance VMs (VLAN 10)
* **190 - 199:** Finance Honeypots (VLAN 10)
* **200 - 289:** Real Operations VMs (VLAN 20)
* **290 - 299:** Operations Honeypots (VLAN 20)
* **300 - 389:** Real Enterprise VMs & Jumpboxes (VLAN 30)
* **390 - 399:** Enterprise Honeypots (VLAN 30)
* **400 - 489:** Real SOC VMs (Vazuh, SIEM) (VLAN 40)
* **490 - 499:** NetOsis LLM Controllers (VLAN 40)

## 4. OPNsense Routing & NAT (External Attack Vector)
The Kali VM sits on `vmbr0` (Fake Internet) and attacks the OPNsense WAN interface. OPNsense Port Forwarding (NAT) routes the traffic into the isolated VLANs:
* **WAN Port 80 (HTTP)** -> Forwards to Real Enterprise Web Server (e.g. `192.168.30.31`)
* **WAN Port 22 (SSH)** -> Forwards to NetOsis SSH Honeypot (`192.168.30.10:2222`)

## 5. Security & Isolation
Real employees are deployed as **Linked Clones** from a golden template.
Honeypots (HHPs) are deployed as lightweight **LXC Containers**.

To protect the real employees from a compromised Honeypot LXC container, the **Proxmox Hypervisor Firewall** (Microsegmentation) is enabled on the LXC container to drop all outbound traffic originating from the Honeypot to the local subnet.
