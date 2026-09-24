# Local LLM for NetOsis (CPU lab host)

## Hardware assumption

- No GPU (or GPU reserved for something else)
- ~48GB RAM, ~24 CPUs
- Proxmox / lab VMs share the same machine → **leave headroom**

## Recommended model

| Role | Model | Why |
|------|--------|-----|
| **Default** | **`qwen2.5:3b`** (Ollama) | Fits CPU-only; ~2–3GB RAM; leaves power for the lab |
| Upgrade | `qwen2.5:7b` Q4 | Better prose; slower; only if 3B is too weak |
| Avoid | 14B+ / full FP16 7B on CPU | Starves the lab |

Embeddings stay light: `sentence-transformers/all-MiniLM-L6-v2` (optional).

## Quick start (Ollama)

```bash
ollama pull qwen2.5:3b

# From NetOsis repo
cp .env.example .env
# ensure:
#   NETOSIS_LLM_MODE=qwen
#   NETOSIS_LLM_BASE_URL=http://127.0.0.1:11434/v1
#   NETOSIS_LLM_MODEL=qwen2.5:3b

source .venv/bin/activate
python -m deception.runtime.cli
# try unknown cmds: uname -a / id / man corp_backup
```

CI / offline demos keep `NETOSIS_LLM_MODE=mock` (no Ollama required).

## CPU / RAM hygiene

- Do **not** pin all 24 cores to Ollama. Prefer ~**8–12** threads so VMs stay responsive.
  Example Ollama env: `OLLAMA_NUM_PARALLEL=1` and limit threads in the Modelfile / server settings.
- Cap generation: `NETOSIS_LLM_MAX_TOKENS=256` (default) — shell replies should be short.
- Keep `NETOSIS_LLM_TEMPERATURE=0.2` so the model stays closer to retrieved evidence.

## RAG corpus

Static lore (VLAN notes, fake man pages) lives in `rag/corpus/` and is indexed
with virtual host state. Antigravity owns those docs; Cursor owns the retriever.

## Failure modes

| Symptom | Check |
|---------|--------|
| `LLM unreachable` | Is `ollama serve` running? Port 11434? |
| Slow replies | Drop to 3B; lower `max_tokens`; free RAM from idle VMs |
| Invented IPs | Tighten corpus; confirm prompt still says “ONLY retrieved evidence” |
| Tests fail offline | `NETOSIS_LLM_MODE=mock` and `NETOSIS_EMBED_MODE=hash` |

## Related

- [docs/rag.md](rag.md) — ingest / retrieve / generate pipeline
- [SECURITY.md](../SECURITY.md) — never commit real API keys or VPN secrets
