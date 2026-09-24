# HANDOFF — Cursor ↔ Antigravity

Shared whiteboard for dual-agent work. Update when you finish a chunk.

## Locked decisions

- Priority: software-first vertical slice (not Proxmox/OPNsense cutover)
- Effort: full days for Phase 0 → thin Phases 1–5
- LLM is not the controller

## Ownership

| Owner | Owns |
|-------|------|
| Cursor | Scaffolding, command engine, telemetry, policy wiring, tests |
| Antigravity | Extra host YAML content, ATT&CK mapping tables, demo narrative in docs |

Do not both edit the same runtime module at once.

## Current status

| Area | Status | Notes |
|------|--------|-------|
| Phase 0 docs/config/scripts | done | Git, docs, vlans.yml, lab-access, HANDOFF |
| HHP command engine | done | pwd/ls/cat/whoami/cd + unit tests |
| Telemetry / ATT&CK / graph / D01 | done | JSONL + mapper + graph + D01 demo |

## Next task

Deepen adaptive deception (D02–D08), more commands, or lab VLAN work with human approval.

## Log

- 2026-09-25 | Cursor | Phase 0–5 thin vertical slice implemented (see README)
