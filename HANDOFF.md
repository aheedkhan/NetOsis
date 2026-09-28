# HANDOFF

## Read first

[`docs/OPNSENSE_SDN_GUIDE.md`](docs/OPNSENSE_SDN_GUIDE.md) — SDN, flows, **Kea DHCP** (why no DHCPv4 menu).

## Locked

- SDN zone `fypzone` + VNets FIN/OPS/ENT/SOC on `vmbr1`
- IP: HHP `.1–.30`, static reals `.31–.99`, DHCP `.100–.200`, GW `.254`
- HHP may reach **SOC only**; must not initiate to real `.31–.253`
- External story: Kali on `vmbr0` → WAN NAT → web `.40` / SSH HHP `.10:2222`

## User now

Configure **Services → Kea DHCP → Subnets** for VLANs 10/20/30/40 (pools `.100–.200`).

## Log

- 2026-09-27 | Cursor | SSH banner OpenSSH-like for nmap; RAG vs NVIDIA docs; corpus `services_and_banners.md`; `[llm]` demo mark
- 2026-09-27 | Cursor | Ingest OPNSENSE_SDN_GUIDE; Kea DHCP; fix HHP→SOC allow in policy notes
