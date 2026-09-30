# Proxmox + OPNsense firewall matrix (intentional loopholes)

## Status

Documentation for lab apply — **do not auto-change** OPNsense/Proxmox without user approval.

## WAN (looks secure)

| Proto | Port | Action | Destination | Story |
|-------|------|--------|-------------|--------|
| TCP | 80 | allow + NAT | `192.168.30.40:80` | Real website |
| TCP | 22 | allow + NAT | `192.168.30.10:2222` | **Intentional** SSH → WEB-HP |
| other | * | filtered/deny | — | Competent perimeter |

Never NAT Proxmox UI, ENT-JUMP, FIN/OPS `.50`, or SOC to WAN.

## Inter-VLAN (OPNsense)

* Default deny between FIN / OPS / ENT / SOC except:
  * HHP (`.10`) → SOC `.31` (Ollama + sandbox API) **allow**
  * ENT-JUMP → reals (admin path) as needed for ops
* HHP → other VLAN reals **deny**

## Same-VLAN L2 (critical)

OPNsense does **not** see HHP↔real on same bridge. Enforce on **each HHP LXC** Proxmox firewall:

* OUT default deny
* Allow UDP/TCP to `192.168.40.31` (SOC)
* Optional: allow TCP/80 to `192.168.30.40` from WEB-HP only (neighbor realism)
* Deny to `.31–.253` on local VLAN (protect `.50` / admin)

## Inside-HP nmap story

Day-0: self + `.40` http open; admin/gw/other VLANs filtered; FIN/OPS HPs not open until earned.
