# RAG + LLM pipeline

Fully local: no external API calls, no cloud model. Everything (embeddings,
generation, the fake Ubuntu system) runs on the SOC controller (Ollama) or in
the engine itself.

## What is special about NetOsis?

| Idea | Why it matters (viva) |
|------|------------------------|
| **LLM is not the controller** | Deterministic engine answers `pwd`/`ls`/`cat`/`find`/`grep`/`nmap`/`ping`/`uname`/`df`/`free`/... from real host state; policy (D01–D07) decides deception — explainable, not "AI magic" |
| **Full fake Ubuntu system** | `/etc/passwd`, `/etc/shadow`, real permissions, old timestamps, a process table and listening sockets are generated once per host (`deception/system/pack.py`) so every answer is self-consistent |
| **RAG grounds hallucinations** | Only genuinely unemulated commands reach the LLM, and even then with evidence from the virtual FS + `rag/corpus/` first |
| **Deception + ATT&CK + graph** | Not just a chatbot shell — telemetry, techniques, adaptive bait |
| **Demo marks** | `[llm]` prefix shows what Qwen produced vs deterministic output |

## Pipeline stages (lab-scale, not a clone of any vendor product)

| Stage | NetOsis (this repo) |
|-------|---------------------|
| Ingest | Virtual host YAML + generated system facts (`deception/system/pack.py`) + `rag/corpus/*.md` |
| Embed / index | MiniLM when installed, else a hash embedder — in-memory, no vector DB needed at this scale |
| Retrieve | Dense + lexical + forced hits (host identity, this attacker's own mutations, command-effects lore) |
| Generate | **Qwen2.5** via Ollama on the SOC controller (0.5b live, 3b for offline cache pre-warm) — CPU-only, no GPU |
| Guardrails | `_LEAK_RE` strips any line that would reveal the deception; policy engine still owns adaptation, not the LLM |

## Flow (unknown shell command)

```text
attacker types command
  → deterministic engine?  yes → real host-state answer (no [llm])
  → not a real Linux binary → instant "command not found" (no [llm], no LLM call)
  → cached answer for this host/user/command?  yes → instant (no LLM call)
  → retrieve_context()  [ingest host + corpus, embed, top-k]
       → generate_response() [Qwen + evidence]
       → reply prefixed [llm] in demo mode, cached for next time
       → telemetry + ATT&CK (if mapped) + policy ladder
```

## nmap / ping / ssh / curl — LLM or not?

All answered deterministically from `deception/lore/topology.yml` via
`deception/network/theater.py` — **never** the LLM, and never a real socket:

| Action | Who answers |
|--------|-------------|
| `nmap -sV <lab host>`, `ping`, `nc -zv`, `dig`/`nslookup`/`host`, `arp -a` | `deception/network/theater.py` — reads the same topology every honeypot shares, so scans agree with `ps`/`ss` on the target itself |
| `ssh user@<other honeypot>` | Theater decides reachable/pivot/denied; a real pivot (`pivot: true` in topology, host reachable) is intended to relay to that honeypot's real sensor — **not yet wired into `scripts/ssh_honeypot.py`** |
| `uname`/`uptime`/`df`/`free`/`hostname`/`date` | Deterministic from `host.system` facts (`deception/system/pack.py`) — instant, no LLM |
| Random junk (`hello`, a typo) | Instant `command not found` — not a real binary, no LLM call |
| A real binary the engine has no branch for (e.g. `strace`) | **LLM (+ RAG)** → `[llm]` + whatever Qwen produces from evidence |

Nothing in a honeypot's fake shell ever performs a real network scan or real
socket connection to anything outside its own virtual filesystem/topology —
only the honeypot's SSH front-door itself does real I/O (accepting the
attacker's real TCP connection).

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

`host.identity` (hostname/OS/IP) is always force-pinned into retrieval
regardless of ranking — with 300+ generated filesystem documents per host, a
plain top-k search could otherwise crowd it out and the LLM would lose the
hostname it's supposed to be answering as.

## Pipes, chains and redirects

`deception/command_engine/shell.py` splits `;` / `&&` / `||` and `|` the same
way bash does (quote-aware), expands `$VAR`/`~`, and implements the common
text filters (`grep`/`head`/`tail`/`wc`/`sort`/`uniq`/`cut`/`awk`/`tr`/`sed`/...)
so `cat /etc/passwd | grep bash`, `find / -perm -4000 2>/dev/null`, and
`mkdir x && cd x` behave like a real shell — entirely deterministic, no LLM.

## Roadmap

Software fake shell first. Later: move the attacker into a **real decoy VM**
without a visible break (the `ssh` pivot groundwork above), then scale many
decoys with Kubernetes + attack-graph mapping. Everything inside a honeypot
session stays theater from lore — never a real scan or a real outbound
connection, except the deliberate real relay to another honeypot sensor once
that wiring is finished.
