# Instructions for Cursor Agent

Authoritative lab networking write-up: **`docs/OPNSENSE_SDN_GUIDE.md`**.

Also see:

- `config/network/vlans.yml` (machine-readable lock)
- `docs/network.md`
- `ops/opnsense/PROPOSED_WAN_NAT.md` (NAT — apply only with user approval)
- `NetOsis_NETWORK_PLAN_UPDATED.xlsx`

### OPNsense 24.x DHCP

There is **no** classic **Services → DHCPv4**. Use **Services → Kea DHCP** (subnets/pools `.100–.200`, gateway `.254`). Optionally Dnsmasq if that is what the lab enabled instead.

### Do not

- Auto-change Proxmox bridges / OPNsense without explicit approval
- Blanket-block HHP → entire VLAN 40 (LLM/controller need SOC reachability)
