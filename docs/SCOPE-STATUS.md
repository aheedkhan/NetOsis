# CyberSnare — scope alignment (design record vs implementation)

This file maps the **approved FYP design** (`docs/src/`) to what is built in the local lab,
what is deliberately deferred, and what is **out of scope** for milestone 1.

## In scope and implemented (P1–P3 lab)

| Design item | Phase | Status |
|-------------|-------|--------|
| Four planes (sensor, decision, deception, intelligence) | P1+ | **Done** — Zeek, logger, decision, surfaces, sinkhole, intelligence (`:18090`) |
| Canonical JSONL event envelope | P1 | **Done** — `config/event-schema.json`, append-only log |
| Zeek HASSH + JA4 | P1 | **Done** — shared deception netns |
| SSH deception (real KEX) | P2 | **Done** |
| HTTPS deception (TLS, JA4) | P2 | **Done** — HTTPS-only on `:8443` |
| Manifest + actuator reconciliation | P2 | **Done** — surfaces poll `/v1/manifest` |
| Policies P0 / P1 / P2 | P2–P3 | **Done** — `./cs up`, `./cs up-adaptive`, `./cs up-p2` |
| GNN scorer (evidence, not verdict) | P2 | **Done** — CPU torch, optional overlay |
| Stage-0 sinkhole egress | P3 | **Done** — DNS + HTTP sinkhole |
| Sandbox isolation | P3 | **Done** — caps dropped, read-only, limits |
| §4.5 auth gate (19 properties) | P3 | **Done** — `./cs gate` (19/19 with lab approval file) |
| L2 restricted shell | P3 | **Done** — `./cs set-level L2`, `./scripts/verify-l2.sh` |
| Slow-path intent inference | P3 | **Done** — rules + optional LLM (`CS_LLM_ENABLED=1`) |
| BURN manifest | P3 | **Done** — `manifest-burn.json`, P1/P2 suspicion path |

## In scope but not yet complete

| Design item | Phase | Gap |
|-------------|-------|-----|
| Supervisor signature (gate #19) | P3 | Lab placeholder on file — replace with signed approval before production |
| ≥4 weeks three-arm data collection | P5 | Scripts ready (`./cs collect`, `./cs redteam`); collection not run |
| Human realism study (5 participants) | P5 | Optional per design record §11.7 |
| Suricata enricher | P1 | **Explicitly deferrable** per execution plan §11.3 |
| LLM with grammar-constrained decoding | P3 | Optional OpenAI-compatible path; no local Qwen host |
| Stage-1 egress | P5 optional | Not built (by design until approved) |

## Milestone 1 lab package (P4–P5 artefacts)

| Item | Status |
|------|--------|
| Intelligence service + dashboard | **Done** — `http://127.0.0.1:18090/` |
| ATT&CK/Engage enrichment | **Done** — `lib/cs/mappings.py`, `lib/cs/intelligence.py` |
| Pre-registration + analysis plan | **Done** — `docs/milestone1/` |
| Red-team profiles | **Done** — `./cs redteam` |
| A/A validation | **Done** — `./cs aa-validate` |
| Milestone analysis | **Done** — `./cs analyze` → `data/milestone1-report.json` |
| Full milestone verify | **Done** — `./cs milestone` |

## Post–milestone 1 (design record §11.1 — do not claim as done)

| Item | Phase | Note |
|------|-------|------|
| L3 immerse actuators (populated FS, internal hop) | **P6** | Manifest + decoy nginx only; no full immerse |
| Artifact generation at scale | P6 | Not started |
| Policy P3 (learned over corpus) | **P7** | Not started |
| Full k3s production deployment | P6+ | `deploy/k8s/` scaffolding only |
| WireGuard + public edge live | Org | `deploy/org/` scripts; local lab uses `127.0.0.1` only |
| Elasticsearch / DuckDB query layer | P4 | Optional over JSONL — not required |

## Explicitly out of scope (do not build in this repo pass)

- Arbitrary outbound TCP from sandbox (“log and allow”)
- LLM in the **fast** request path (<100 ms budget)
- Listening on `0.0.0.0` for the local lab contract
- Real org data or real internet egress from deception

## Commands

```bash
./cs verify              # P1/P2 vertical slice (16 checks)
./cs gate                # §4.5 nineteen properties
./cs milestone           # Full milestone 1 verification
./cs set-level L2        # Pin L2 manifest (after gate)
./cs verify-l2           # L2 engage smoke test
./cs up-adaptive         # Arm B — P1 + GNN + intent worker
./cs up-p2               # Arm C — P2 intent-conditioned policy
./cs redteam             # Scripted evaluation profiles
./cs analyze             # Milestone report JSON
./cs monitor             # Live actor activity
./cs collect             # Daily collection snapshot
```

## Alignment verdict

The local lab satisfies **milestone 1 lab readiness** (P1–P5 artefacts, `./cs milestone` passes).
Remaining thesis work: run the three-arm study for ≥4 weeks, optional human realism study, and
replace the lab supervisor approval file with a signed copy. **L3 immerse, org WireGuard, and
Suricata** are post-milestone or deferrable per the design record.
