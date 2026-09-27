# Proposed OPNsense WAN NAT (fake Internet)

## Status: PROPOSAL ONLY

Do not apply until the user explicitly approves. Agents must not change OPNsense automatically.

## Story

`vmbr0` (`172.30.226.0/24`) is the lab **fake Internet**.

| Host | Example IP | Role |
|------|------------|------|
| Kali | `172.30.226.50` | External attacker |
| OPNsense WAN | `172.30.226.100` | Corporate “public IP” |
| Proxmox | `172.30.226.7` | Hypervisor (not a target) |

## Port forwards (Firewall → NAT → Port Forward)

| WAN (dest) | Proto | Port | Redirect to | Notes |
|------------|-------|------|-------------|--------|
| WAN address | TCP | 80 | `192.168.30.40:80` | Real enterprise web |
| WAN address | TCP | 443 | `192.168.30.40:443` | Optional if HTTPS later |
| WAN address | TCP | 22 | `192.168.30.10:2222` | NetOsis SSH HHP |

Associated firewall rules on WAN: allow those ports only from lab/Kali ranges if you want tighter control.

## Attack demo

```bash
# On Kali (vmbr0)
nmap -sV 172.30.226.100
curl -I http://172.30.226.100/
ssh admin@172.30.226.100   # lands in fake shell (any password)
```

## Must not

- Forward management services (Proxmox UI, SSH to hypervisor) from WAN.
- Expose `172.30.226.0/24` to the real Internet.
- Put Kali on VLAN 30 for the *external* story (use vmbr0 for that scenario).
