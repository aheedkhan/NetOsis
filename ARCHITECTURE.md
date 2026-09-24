# Architecture

## Purpose

NetOsis exposes a high-interaction honeypot (HHP), records structured telemetry,
maps behavior to MITRE ATT&CK, maintains a dynamic attack graph, and applies
deterministic policy to adapt deception. The system must stay explainable for
an FYP viva.

## Spine

```text
network isolation
  → telemetry
  → actor / profile
  → attack graph
  → MITRE ATT&CK
  → policy
  → adaptive deception
```

## Critical rule: LLM is not the controller

Authoritative state is YAML/JSON. Simple shell commands are answered by a
deterministic command engine. RAG + LLM may later help with complex interaction,
but policy validates any adaptive action. The LLM must not invent host state,
act as firewall, or be the sole risk engine.

## First vertical slice

```text
Public HHP / CLI
  → login / session
  → fake shell (pwd, ls, cat, whoami)
  → telemetry event
  → ATT&CK mapping
  → attack graph update
  → policy → D01 expose fake host
```

## Components (slice)

| Component | Inputs | Outputs |
|-----------|--------|---------|
| Virtual host YAML | hostname, FS, users, network | Loaded host state |
| Command engine | command + session + host | stdout/stderr + cwd |
| Telemetry store | normalized events | JSONL on disk |
| ATT&CK mapper | event + behavior | technique id + confidence |
| Attack graph | mapped events | nodes/edges (JSON) |
| Policy engine | risk score + graph | allowed deception action |

## Security assumptions

- Management network `172.30.226.0/24` is off-limits to attackers.
- Fake hosts are emulated; real malware is never executed on the Fedora host.
- Secrets are local paths only; never committed.

## Failure modes

- Missing host YAML → shell fails closed with a clear error.
- Unknown command → deterministic “command not found”; no LLM fallback in slice.
- Policy below threshold → no deception action; state unchanged.

## Resource requirements

Single Python process; JSONL + in-memory/file graph. No GPU required for the slice.

## Tests

Unit tests for commands; scenario test for the vertical slice happy path.
