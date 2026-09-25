# HANDOFF — Cursor ↔ Antigravity

## Locked decisions

- Default local LLM: **`qwen2.5:3b`** (not the 27B/30B models already on this host)
- SSH front-door: `scripts/ssh_honeypot.py` on port **2222**
- LLM is fallback only; RAG indexes virtual host + `rag/corpus/`

## Ownership

| Owner | Owns |
|-------|------|
| Cursor | Pipeline, RAG, SSH honeypot hardening, docs |
| Antigravity | `rag/corpus/*`, canary/host YAML polish |

## Status

| Item | Status |
|------|--------|
| SSH honeypot script | done (`scripts/ssh_honeypot.py`) |
| docs/ssh-honeypot.md | done |
| qwen2.5:3b pulled | check `ollama list` — do not use 27B/30B for this |
| paramiko in venv | install via `pip install -r requirements.txt` |

## Real test checklist

1. `ollama pull qwen2.5:3b` finishes
2. `.env` has `NETOSIS_LLM_MODE=qwen` + `NETOSIS_LLM_MODEL=qwen2.5:3b`
3. `python scripts/ssh_honeypot.py --port 2222`
4. `ssh admin@<ip> -p 2222` → try `ip route` then `man corp_backup.sh`

## Log

- 2026-09-25 | Antigravity | corpus docs + first ssh_honeypot.py
- 2026-09-25 | Cursor | harden SSH honeypot, docs, defaults to 3B, paramiko req
- 2026-09-25 | Antigravity | Audited Phase 3. SSH Honeypot fixed. Delegated Phase 4/5 (Proxmox Lab Deployment & Remote Access) to Cursor.
