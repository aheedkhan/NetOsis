# NetOsis Network Model

## Purpose

Document the locked lab topology so software and infrastructure stay aligned.
Authoritative machine-readable config: `config/network/vlans.yml`.

## Management / upstream

| Item | Value |
|------|-------|
| Subnet | `172.30.226.0/24` |
| Proxmox | `172.30.226.7/24` on `vmbr0` |
| Gateway | `172.30.226.254` |

This network is for lab management only. Do not expose it to attackers.
Do not redesign it into an OPNsense internal management VLAN.

## FYP trunk

Proxmox bridge `vmbr1` is VLAN-aware and carries FYP VLANs toward OPNsense.

## Locked VLANs

| VLAN | Name | Subnet | Gateway | Purpose |
|------|------|--------|---------|---------|
| 10 | FINANCE | `192.168.10.0/24` | `192.168.10.254` | Finance |
| 20 | OPERATIONS | `192.168.20.0/24` | `192.168.20.254` | Operations |
| 30 | ENTERPRISE | `192.168.30.0/24` | `192.168.30.254` | Enterprise / public-facing test |
| 40 | SOC | `192.168.40.0/24` | `192.168.40.254` | SOC / telemetry / controller |

Existing VLAN 250 remains. Use `/24` and `.254` gateways — not the older `/28` / `.1` spreadsheet.

## Deception vs real hosts

Most apparent hosts are virtual/emulated (YAML state), not one VM per fake host.
Real employee VMs are documented in `docs/employee-vms.md`.

## Lab access

From the Fedora workstation:

1. OpenVPN using local config under `/home/mania/Documents/server/`
2. Tunnel `tun0`
3. FreeRDP to jump box `172.30.227.1`

Safe wrappers (no embedded secrets): `scripts/lab-access/`.

## Security assumptions

- Attackers never reach `172.30.226.0/24` management.
- Secrets stay on the workstation; paths are referenced via `.env`, not Git.
- Infrastructure changes (Proxmox / OPNsense) require explicit human approval.
