# HANDOFF — Cursor ↔ Antigravity

## Locked decisions

- Default local LLM: **`qwen2.5:3b`** (CPU-friendly; see `docs/llm-local.md`)
- LLM is fallback only; RAG indexes virtual host + `rag/corpus/`
- Do not both edit `deception/llm/fallback.py` / `command_engine/engine.py`

## Ownership

| Owner | Owns |
|-------|------|
| Cursor | RAG ingest/retrieve, Qwen client defaults, `docs/llm-local.md` |
| Antigravity | `rag/corpus/*` lore (topology, tools, architecture) |

## Status

| Item | Status |
|------|--------|
| Defaults → qwen2.5:3b + Ollama :11434 | done |
| Index `rag/corpus/*.md` in `build_corpus()` | done |
| docs/llm-local.md | done |

## Log

- 2026-09-25 | Antigravity | corpus: network_topology, internal_tools, system_architecture
- 2026-09-25 | Cursor | wire 3B defaults + ingest static corpus + llm-local.md
