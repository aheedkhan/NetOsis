# Milestone 1 — Pre-registration (analysis plan)

**Status:** Template — date and sign before formal three-arm collection begins.

## Research questions (from design record §7)

1. **RQ1:** Does adaptive escalation (Arm B vs A) improve engagement depth and intelligence yield?
2. **RQ2:** Does intent-conditioned deception + realism (Arm C vs B) reduce suspicion and increase yield?
3. **RQ3:** Does the control loop meet the stated actuation latency budget (<1 s manifest reconcile)?

## Experimental arms

| Arm | Policy | Configuration |
|-----|--------|---------------|
| A | P0 | `./cs up` — static manifest |
| B | P1 | `./cs up-adaptive` — utility + GNN |
| C | P2 | `./cs up-p2` — intent-conditioned |

## Primary outcomes

- Engagement depth (unique datasets per actor, session duration proxy)
- Intelligence yield (shell commands, sinkhole fetches, credential attempts)
- Manifest transitions per actor (dynamic deception events)
- Suspicion signals (vm_check, proc_read datasets)

## Analysis plan

1. Export JSONL via `data/events/events.jsonl` (system of record).
2. Run `./cs analyze` for arm summary JSON.
3. Compare arms on event counts, actor counts, transitions (Kaplan–Meier deferred until ≥4 weeks data).
4. Report null results if arms do not differ.

## Exclusions

- No real internet egress (stage 0 sinkhole only).
- Human realism study (5 participants) — optional descope per §11.7.

## Sign-off

| Role | Name | Date |
|------|------|------|
| Student | | |
| Supervisor | | |
