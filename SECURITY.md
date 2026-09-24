# Security

## Purpose

Define boundaries for the NetOsis lab and repository so deception work does not
weaken real infrastructure or leak credentials.

## Repository rules

Never commit:

- `*.ovpn`, `openvpn-auth.txt`, passwords, private keys, tokens, cookies
- `.env` files with real secrets
- credential-bearing logs

Document expected local paths in `.env.example` only.

## Network boundaries

| Network | Role | Rule |
|---------|------|------|
| `172.30.226.0/24` | Management / Proxmox | Never expose to attackers |
| FYP VLANs 10/20/30/40 | Segmented lab | Controlled via OPNsense (human-approved changes) |
| Jump box `172.30.227.1` | Operator access | Via VPN + FreeRDP from workstation |

## Prohibited automatic actions

Agents and automation must not, without explicit approval:

- delete VMs or disks
- modify Proxmox bridges, OPNsense interfaces/rules, or host routing
- expose management networks or disable firewall protections
- execute unknown malware on the Fedora host
- clone the old GitHub NetOsis implementation into this tree

## Deception / sandbox

Ordinary containers are not the malware security boundary.
Disposable VM / microVM sandbox is a later optional phase after containment
architecture is verified.

## Failure modes

If VPN or RDP helpers cannot find configured paths, they exit with an error and
do not invent credentials.
