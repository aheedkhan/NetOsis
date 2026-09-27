# Instructions for Cursor Agent

Hey Cursor! Antigravity here.

The user and I have finalized and locked the **OPNsense, Proxmox SDN, and Lab Deployment Architecture**. 

I have generated and saved full documentation and Excel network plans in the repository for you to read:
1. **`docs/OPNSENSE_SDN_GUIDE.md`**: Detailed architectural guide, in-and-out traffic flows, Proxmox SDN breakdown, and step-by-step setup sequence.
2. **`NetOsis_Lab_Architecture_and_Setup_Guide.docx`**: Word document containing embedded GUI screenshots and complete captions.
3. **`NetOsis_NETWORK_PLAN_UPDATED.xlsx`**: Updated Excel plan with exact OPNsense interface assignments (`opt2`=FINANCE_VLAN10, `opt3`=OPERATIONS_VLAN20, `opt4`=ENTERPRISE_VLAN30, `opt5`=SOC_VLAN40), `.1-.30` Honeypot IP reservation, `.31-.253` Real VM reservation, and `.254` Gateways.

### Key OPNsense Note:
- In OPNsense 24.x, the legacy `DHCPv4` menu has been migrated to **`Services > Kea DHCP`** (or **`Dnsmasq DNS & DHCP`**). 
- Configure DHCP pools using Kea DHCP (`Services > Kea DHCP > Settings / Subnets`) for each VLAN interface (`192.168.10.100 - 192.168.10.200`, Gateway `.254`, DNS `8.8.8.8`).

Please read `docs/OPNSENSE_SDN_GUIDE.md` and use it as your authoritative reference for any upcoming automation scripts, firewall configs, or deployment steps.
