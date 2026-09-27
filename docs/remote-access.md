# Remote access (from work)

## Paths

**Admin (you):** Laptop → OpenVPN → management jumpbox `172.30.227.1` (FreeRDP) → Proxmox/OPNsense.

**Attacker demo (lab):** Kali on `vmbr0` → OPNsense WAN (fake public IP) → NAT → HHP `192.168.30.10:2222` or real web `.40`.

**Direct HHP (after VLAN-30 LXC exists):**

```bash
ssh admin@192.168.30.10 -p 2222
```

**Current Fedora smoke test (if still used):**

```bash
ssh admin@192.168.1.5 -p 2222
```

Do not confuse management jumpbox (`172.30.227.1`) with enterprise jumpbox (`192.168.30.31`).

See `docs/network.md` and `ops/opnsense/PROPOSED_WAN_NAT.md`.
