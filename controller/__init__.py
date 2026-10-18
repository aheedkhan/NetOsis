"""NetOsis controller — runs on the SOC VM (192.168.40.31).

Owns things individual honeypots must not: Proxmox power control (so a
honeypot can never touch the hypervisor) and, later, the real sandbox jobs.
Honeypots only ever talk to it over HTTP on the lab network.
"""
