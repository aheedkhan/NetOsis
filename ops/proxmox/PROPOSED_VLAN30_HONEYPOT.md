# Proposed Proxmox placement — Enterprise HHP on VLAN 30

## Status: PROPOSAL ONLY

## Target

- LXC/VMID **390**, VLAN tag **30**, IP **`192.168.30.10/24`**, GW **`192.168.30.254`**
- HHP listens **2222**; OPNsense may NAT WAN **:22** → this host (see `ops/opnsense/PROPOSED_WAN_NAT.md`)

## Example (after approval)

```bash
# pct set 390 --net0 name=eth0,bridge=vmbr1,tag=30,firewall=1
```

Proxmox FW on this CT: allow TCP 2222 in; default-deny out except SOC if needed.
