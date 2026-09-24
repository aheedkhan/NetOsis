# HANDOFF — Cursor ↔ Antigravity

Shared whiteboard for dual-agent work. Update when you finish a chunk.

## Locked decisions

- Priority: software-first vertical slice (not Proxmox/OPNsense cutover)
- Effort: full days for Phase 0 → thin Phases 1–5, then Phase 6 progressive deception
- LLM is not the controller
- `ps` / `ip` must read virtual host YAML only — never shell out to the real OS

## Ownership

| Owner | Owns |
|-------|------|
| Cursor | Scaffolding, command engine, telemetry, policy wiring, tests |
| Antigravity | Extra host YAML content, ATT&CK mapping tables, demo narrative in docs |

Do not both edit the same runtime module at once (especially `deception/command_engine/engine.py`).

## Current status

| Area | Status | Notes |
|------|--------|-------|
| Phase 0 docs/config/scripts | done | |
| HHP command engine | done | pwd/ls/cat/whoami/cd/ps/ip |
| Telemetry / ATT&CK / graph / D01 | done | |
| Progressive D02–D07 + actor profile | done | Canary body still placeholder |
| D08 sandbox | deferred | |

## Your input needed (canary)

In `deception/artifacts/staged_actions.yml`, under `D05_deploy_canary`:

1. Rename `path` from `TODO_CANARY.txt` to a **believable** enterprise document name (not “honeypot” / “canary”).
2. Replace `content` with 4–8 lines that look like a real internal note.

Trade-off: too cute → attackers spot the trap; too boring → they never open it. Canary hits raise `Canary_interaction` (+6 risk).

## Next task

- Wire canary name/content (you), then optional SSH/web public stub, or lab VLAN work with approval.

## Log

- 2026-09-25 | Cursor | Phase 0–5 thin vertical slice
- 2026-09-25 | Cursor | Phase 6: ps/ip, ladder D01–D07, actor profile, staged artifacts
