# HANDOFF

## Read first

- [`docs/OPNSENSE_SDN_GUIDE.md`](docs/OPNSENSE_SDN_GUIDE.md) — SDN, Kea DHCP
- [`ops/proxmox/FW_HHP_AND_WAN.md`](ops/proxmox/FW_HHP_AND_WAN.md) — FW loopholes + L2 deny
- [`ops/proxmox/LAB_DEPLOY_CHECKLIST.md`](ops/proxmox/LAB_DEPLOY_CHECKLIST.md) — deploy steps (manual approve)

## Locked architecture

- **No employee desktops** — server VLANs only
- **3 LXC HPs** at `.10` (FIN / OPS / WEB); **reals** at `.50` / `.40` / `.31`; **SOC** `.31`
- HHP → SOC only; Proxmox FW denies HHP → reals (same-VLAN)
- WAN NAT: `:80`→`.30.40`, `:22`→`.30.10:2222` (intentional loophole)
- Phase-1 sandbox mock in `deception/runtime/sandbox.py` (no K8s yet)
- RAG personas: `rag/corpus/fake_accounts_and_backups.md`

## Drawbacks & viva mitigations

| Drawback | Mitigation |
|----------|------------|
| No GUI phishing demos | Server lateral is FYP focus; RAM for Qwen/Wazuh |
| LLM 1–3s latency | Deterministic engine for common cmds |
| Fake shell ≠ kernel exploits | Containment; real binaries → sandbox |
| Same-VLAN L2 bypasses OPNsense | Proxmox HHP port firewall |

## User now

1. Review FW + deploy checklists; apply Proxmox/OPNsense only when ready.
2. Optional: Phase-2 `NETOSIS_SANDBOX_URL=http://192.168.40.31:8000` after k3s.

## Log

- 2026-10-01 | Cursor | Phase-1 sandbox stub; personas; ops-app HP; vlans no employees; FW/deploy docs
- 2026-09-27 | Cursor | SSH banner; RAG vs NVIDIA; `[llm]` demo mark
