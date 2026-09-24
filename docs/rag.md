# RAG + Qwen 7B for NetOsis

## Goal

Local RAG for unknown shell commands:
1. Embed / index virtual filesystem + host state
2. Retrieve top-k evidence (`all-MiniLM-L6-v2` when installed)
3. Generate with **Qwen 2.5 7B Instruct** (Ollama / NIM / vLLM)
4. LLM stays a **fallback only** — never the controller

## Modules

| Path | Role |
|------|------|
| `deception/llm/rag.py` | `retrieve_context(session, command)` |
| `deception/llm/fallback.py` | `generate_response(session, command, retrieved_context)` |
| `deception/llm/openai_client.py` | OpenAI-compatible Qwen HTTP client |
| `rag/ingest.py` | Chunk virtual host YAML |
| `rag/retrieval/embeddings.py` | MiniLM or offline hash embedder |
| `rag/retrieval/dense.py` | Cosine dense retrieval |

## Install embeddings (optional but recommended)

```bash
pip install -r requirements-rag.txt
export NETOSIS_EMBED_MODE=minilm   # or auto
```

Without sentence-transformers, `NETOSIS_EMBED_MODE=auto` uses a hash embedder so tests still pass.

## Qwen (CPU lab default: 3B)

```bash
ollama pull qwen2.5:3b
export NETOSIS_LLM_MODE=qwen
export NETOSIS_LLM_BASE_URL=http://127.0.0.1:11434/v1
export NETOSIS_LLM_MODEL=qwen2.5:3b
# upgrade path only if needed: qwen2.5:7b
```

See [llm-local.md](llm-local.md) for RAM/CPU limits on a shared Proxmox host.

## Defaults for CI

```bash
NETOSIS_LLM_MODE=mock
NETOSIS_EMBED_MODE=hash
```

Static lore from Antigravity is loaded from `rag/corpus/*.md` into the same index.
