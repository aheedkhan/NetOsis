# Employee VMs

## Purpose

Real employee workstations for **Finance** and **Operations** only.
Enterprise (VLAN 30) has **no** employee desktops — only servers / enterprise jumpbox / HHP.

## Inventory (IPs in real range `.31+`)

| Name | VLAN | IP | SDN VNet |
|------|------|-----|----------|
| FIN-USER-01 | 10 | `192.168.10.31` | FIN |
| FIN-USER-02 | 10 | `192.168.10.32` | FIN |
| OPS-USER-01 | 20 | `192.168.20.31` | OPS |
| OPS-USER-02 | 20 | `192.168.20.32` | OPS |

## Template workflow

Linked clones from a golden Ubuntu template (VM 102 historically).
Do not bake per-VM IPs into the template. Do **not** clone NetOsis HHP LXCs from the employee template.

## Status

Documentation aligned with `config/network/vlans.yml`. Apply Proxmox clones only with your approval.
