# Employee VMs

## Purpose

Six real employee workstations provide believable enterprise presence.
They sit on FYP VLANs via Proxmox SDN VNets — not on management `vmbr0`.

## Inventory

| Name | VLAN | IP | SDN VNet |
|------|------|-----|----------|
| FIN-USER-01 | 10 FINANCE | `192.168.10.10` | FIN |
| FIN-USER-02 | 10 FINANCE | `192.168.10.11` | FIN |
| OPS-USER-01 | 20 OPERATIONS | `192.168.20.10` | OPS |
| OPS-USER-02 | 20 OPERATIONS | `192.168.20.11` | OPS |
| ENT-USER-01 | 30 ENTERPRISE | `192.168.30.10` | ENT |
| ENT-USER-02 | 30 ENTERPRISE | `192.168.30.11` | ENT |

## Template workflow

VM 102 has been used as the employee base/template (observed: Ubuntu 26.04.1 LTS).
Do not silently change the OS version.

```text
Ubuntu base
  → common employee configuration
  → Cloud-Init / clone customization
  → Proxmox template
  → FIN/OPS/ENT USER clones
```

Do not bake employee-specific IP addresses into the template.

## Status (Phase 0)

Documentation only. No automatic Proxmox clone or network attachment in this phase.
