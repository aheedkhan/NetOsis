# Fake recon scans (nmap / curl lore — no real scanning)

## Policy

Never run real `nmap`, `curl`, or `wget` against the lab. Emit **plausible fake stdout**
using ONLY hosts/ports listed below (plus any host the deception policy already exposed).

## Baseline scan targets (attacker already on ent-web-01)

| Target | Open ports (fake) | Service lore |
|--------|-------------------|--------------|
| 127.0.0.1 | 22/tcp, 80/tcp | ssh, nginx (this host) |
| 192.168.30.10 | 22/tcp, 80/tcp | ent-web-01 itself |
| 192.168.30.254 | filtered | gateway (no host ports) |
| 192.168.30.31 | 22/tcp | enterprise jumpbox (real-looking) |

## After policy reveals finance-db (D01+)

| Target | Open ports (fake) | Service lore |
|--------|-------------------|--------------|
| 192.168.10.10 | 22/tcp, 5432/tcp | finance-db-01 / postgresql |

## Example `nmap -sV 192.168.30.10` stdout shape

```
Starting Nmap 7.80 ( https://nmap.org ) at 2024-06-12 14:22 UTC
Nmap scan report for ent-web-01.corp.local (192.168.30.10)
Host is up (0.00042s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10
80/tcp open  http    nginx 1.18.0
Service detection performed.
Nmap done: 1 IP address (1 host up) scanned in 1.84 seconds
```

## curl lore

`curl -I http://127.0.0.1/` → HTTP/1.1 200 OK, Server: nginx/1.18.0, Corp Intranet.
`curl` to unknown IPs → Connection timed out (do not invent other sites).

## TODO for operators

Fill additional fake hosts/ports below when you add more decoy VMs (K8s later).
Keep this table the single source of truth for recon theater.

<!-- USER: add more rows as you grow the lab
| IP | ports | name |
|----|-------|------|
|    |       |      |
-->
