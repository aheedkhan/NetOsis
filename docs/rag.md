# RAG + LLM pipeline (and vs NVIDIA Blueprint)

## What is special about NetOsis?

| Idea | Why it matters (viva) |
|------|------------------------|
| **LLM is not the controller** | Deterministic YAML answers `pwd`/`ls`/`ip`; policy (D01–D07) decides deception — explainable, not “AI magic” |
| **RAG grounds hallucinations** | Unknown cmds get evidence from virtual FS + `rag/corpus/` before Qwen speaks |
| **Same spine as enterprise RAG** | Ingest → retrieve → generate — like NVIDIA’s blueprint, but lab-scale |
| **Deception + ATT&CK + graph** | Not just a chatbot shell — telemetry, techniques, adaptive bait |
| **Demo marks** | `[llm]` prefix shows what Qwen produced vs deterministic output |

## Is our pipeline like NVIDIA’s RAG Blueprint?

**Same stages, different scale.**

| Stage | NVIDIA Blueprint | NetOsis (this repo) |
|-------|------------------|---------------------|
| Ingest | Multimodal docs → object store | Virtual host YAML + `rag/corpus/*.md` |
| Embed / index | NeMo Retriever NIMs + Elasticsearch/Milvus | MiniLM or hash embedder + in-memory cosine / hybrid lexical |
| Retrieve | Dense + sparse + rerank | Dense + lexical + forced file hits |
| Generate | Large Nemotron / multi-GPU NIMs | **Qwen2.5-3B** via Ollama (CPU-friendly) |
| Guardrails | Optional NemoGuard | Prompt constraints + policy engine still owns adaptation |
| Hardware | Multi-H100 class | Your 48GB RAM / 24 CPU lab host |

So: **conceptually aligned** with [NVIDIA Build a RAG Pipeline](https://build.nvidia.com/nvidia/build-a-rag-pipeline); **not** a clone of their full stack.

## Flow (unknown shell command)

```text
attacker types command
  → deterministic engine?  yes → YAML answer (no [llm])
  → no → retrieve_context()  [ingest host + corpus, embed, top-k]
       → generate_response() [Qwen/mock + evidence]
       → reply prefixed [llm] in demo mode
       → telemetry + ATT&CK (if mapped) + policy ladder
```

## nmap / banner grabbing — LLM or not?

| Action | Who answers |
|--------|-------------|
| `nmap 192.168.1.9 -p 2222` from another host | **Real TCP/SSH stack** (Paramiko). Banner ≈ OpenSSH string. **Not LLM.** |
| After login, `nmap -sV 192.168.30.10` | **Deterministic lore** from `deception/lore/recon_targets.yml` (no `[llm]`, no real scan) |
| After login, random junk (`hello`) | **LLM (+ RAG)** → `[llm]` + command not found |
| `pwd` / `ls` / `ip a` / `sudo su` / `apt install` | **Deterministic** — elevate / apt theater / YAML |

## Phase-1 sandbox (external curl/git)

External `curl`/`wget`/`git clone`/`./payload` → `deception/runtime/sandbox.py` (mock).
Files land in Session virtual FS + `actor.sandbox:*` RAG docs. Malware IPs in
`deception/lore/malware_ips.yml` are contained (timeout cover). Phase-2: set
`NETOSIS_SANDBOX_URL` to SOC API.

`mkdir` / `touch` / `echo >` / `rm` / `apt install`:

1. **Engine** mutates virtual FS / packages (source of truth — no hallucination of paths)
2. **RAG** injects an AUTHORITATIVE MUTATION RECORD + `command_effects.md` (real Ubuntu behavior)
3. **LLM** only prints what a real shell would (usually empty on success; apt theater text)

LLM must not invent files that were not created. Errors stay deterministic (stderr from engine).

Each attacker is keyed by `actor_id` (SSH peer IP → `actor-<ip>`).

* Profiles persist under `data/profiles/<actor_id>.json`
* RAG rebuild includes **this** attacker's mutations + labeled profiles
* Other hackers appear as `OTHER attacker` docs (never mixed into shell ownership)
* Set `NETOSIS_RAG_MULTI_ACTOR=0` to hide other profiles from retrieve

## Live FS mutations → RAG

`mkdir` / `touch` / `echo >` / `rm` mutate the **virtual** filesystem on the session.
Each LLM retrieve rebuilds the corpus from that state:

* create path → appears as `fs:` / `fsdir:` (and `actor.mutations`)
* delete path → dropped from the index
* `apt install X` → recorded in `packages_attempted` (theater only) for profiling


Software fake shell first. Later: move the attacker into a **real decoy VM** without a
visible break, then scale many decoys with **Kubernetes** + attack-graph mapping.
Until then: inside-session nmap/curl/apt are **theater from lore**, never real tools.
