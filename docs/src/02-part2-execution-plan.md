\part{PART II — EXECUTION PLAN}

# 10. Flows

Part I introduced the figures where they carried an argument. This section walks the four flows that
matter operationally, step by step, so that an implementer can follow each one without re-reading the
design rationale.

## 10.1 Flow A — A connection arrives

The most common path through the system, executed thousands of times a day.

| # | Step | Plane | Budget |
|---|---|---|---|
| 1 | Packet reaches the exposure point; Zeek records the connection and extracts client fingerprints | Sensor | — |
| 2 | Deception surface accepts the connection and emits a canonical event over a unix socket | Deception | — |
| 3 | Decision plane resolves the actor: existing `actor_key` by fingerprint match, or a new one | Decision | < 10 ms |
| 4 | Belief state updated — capability, engagement, suspicion, novelty; behavioural score recomputed as one feature among several | Decision | < 30 ms |
| 5 | Active policy evaluates the action space and emits a surface manifest | Decision | < 60 ms |
| 6 | Actuator reconciles reality toward the manifest, using only pre-staged capabilities | Deception | < 1 s |
| 7 | Event appended to the log; slow path indexes it for the intelligence plane | Intelligence | seconds |

Steps 3 to 5 constitute the control loop and must complete within the **100 ms decision budget** of
§6.4. Step 7 is explicitly outside that budget and must never be allowed to enter it — the single most
likely way for this design to regress during implementation is for a convenient database read to creep
into step 4.

## 10.2 Flow B — Escalation

The flow the whole system exists to perform.

1. Belief state crosses a policy-relevant boundary — not a fixed score threshold, but a change in the
   inferred objective distribution or in confidence about it.
2. The policy emits a manifest naming additional capabilities: authentication enabled, a populated
   filesystem, an additional listening service.
3. The actuator binds an already-warm capability to the actor. Nothing is created; something
   pre-staged is *attached*.
4. The change takes effect on the adversary's **next connection**, not mid-session. This is a stated
   limitation, not an oversight — a live SSH session cannot be swapped after key exchange, and
   attempting it would break the transport in a way no real server ever does.
5. The transition is recorded with the manifest identifier, the rationale, and the Engage activity
   identifier for what was exposed.

## 10.3 Flow C — Egress attempt

The second evidence stream (§5.1), and the flow with the strictest safety properties.

1. A process inside the sandbox resolves a name. The gateway's DNS proxy answers and logs the query.
2. At **stage 0**, the answer points back at the gateway. The subsequent connection is served by an
   instrumented responder: the adversary observes success, and nothing reaches the internet.
3. Connection metadata, requested URL, user-agent, retry behaviour and intended payload name are all
   captured and correlated with the session's command telemetry.
4. Any traffic outside the allowlist is denied by default and recorded as a policy decision — itself a
   high-value intent signal.
5. If the outbound connection rate crosses the circuit-breaker threshold, the sandbox is torn down
   automatically and the event is escalated.

## 10.4 Flow D — Suspicion and withdrawal

The flow with no analogue in the surveyed literature.

1. Fingerprinting behaviour is detected — `/proc` and `dmesg` reads, virtualisation checks, timing
   probes, repeated identical commands testing for determinism.
2. `suspicion` rises in the belief state.
3. The policy's risk term `μ·P(blown | belief, a)` begins to dominate, and the expected value of
   further escalation turns negative.
4. The session transitions to **BURN**: capabilities are frozen rather than extended, remaining
   evidence is harvested, and the adversary is allowed to disengage.
5. The fingerprinting technique that succeeded is recorded as a defect against the deception surface —
   which makes `suspicion` a feedback signal for improving realism, not merely a trigger.

## 10.5 Phase dependencies

![Phase dependency graph with the three decision checkpoints](figures/f10-phase-dependencies.svg)

The graph makes the hard gates visible. Nothing in P3 begins until the authentication gate passes.
Nothing in P5 is analysable unless pre-registration preceded exposure. And the A/A validation in P1
must conclude before any treatment arm is enabled, because a failed A/A invalidates every comparison
that follows it.

\pagebreak

# 11. Phases

## 11.1 Overview

| Phase | Weeks | Objective | Exit criterion |
|---|---|---|---|
| **P0** Design & approval | pre-W1 | This record; approvals; procurement; taxonomy | Record signed off; exposure configuration decided |
| **P1** Sensing & ground truth | W1–2 | Sensor plane, canonical event log, observe-only exposure | A/A validation running; one real scan visible end to end |
| **P2** Deception surfaces | W3 | Custom SSH and HTTP; manifest and reconciliation; P0/P1 | **Arm B live**; sandbox built, authentication closed |
| **P3** Interaction & intent | W4 | Authentication gate; restricted shell; stage-0 egress; P2 | **Arm C live**; three-arm collection begins |
| **P4** Intelligence | W5–6 | ATT&CK and Engage mapping; timelines; profiles; reports | Analyst can reconstruct any session end to end |
| **P5** Evaluation | W7–8 | Red-team profiles; realism study; analysis; write-up | **Milestone 1 complete and demonstrable standalone** |
| **P6** Immersive environments | post | L3 Immerse; orchestration; artifact generation at scale | — |
| **P7** Learned policy | post | Policy P3 over the collected corpus | — |
| **P8** Final evaluation & thesis | post | Full evaluation; thesis; defence | — |

## 11.2 P0 — Design and approval

**Objective.** Establish the design, secure the approvals, and resolve the decisions that later phases
cannot proceed without.

**Entry gate.** None. This is the origin.

**Work.** Sign-off on this record. Supervisor approval for accepting SSH authentication and for staged
egress. Exposure configuration decided and, if purchased, provisioned. Provider terms of service
confirmed. **Objective taxonomy drafted** — the closed set of intents that P2 will condition on.

**Exit criterion.** Record signed; exposure configuration decided; approvals in writing.

**Deliverable.** This document, signed. **Owner.** Whole team.

**Descope.** Nothing. P0 is not descopable; every item in it gates something later.

## 11.3 P1 — Sensing and ground truth

**Objective.** Establish that events can be captured, normalised, stored and queried, and begin
collecting data immediately — dataset time is the one resource that cannot be recovered later.

**Entry gate.** Server specification known; VLAN separation in place; exposure reachable.

**Work.** Zeek deployed with HASSH and JA4 extraction. Suricata deployed as enricher. Canonical event
envelope frozen. Append-only log with disk-fill guard. Observe-only deception surfaces exposed.
Actor-linkage v0. **A/A validation begins.** Objective taxonomy frozen (week 2). Pre-registration
written.

**Exit criterion.** A port scan performed from an external host appears as a correctly normalised event
with the right source, actor key and technique mapping — a complete vertical slice through all four
planes.

**Deliverable.** Sensor plane, event log, schema v1, pre-registration.
**Owner.** Eman Azam (sensors), Sara Sultan (log and schema), Uliya Fatima (infrastructure).

**Descope.** Suricata may be deferred; Zeek may not.

## 11.4 P2 — Deception surfaces

**Objective.** Replace observe-only placeholders with genuine deception surfaces, and stand up the
decision plane so that arm B becomes meaningful.

**Entry gate.** P1 exit criterion met; A/A validation showing no material imbalance, or its imbalance
quantified.

**Work.** Custom SSH surface in Python `asyncio` — full transport handshake, client version and HASSH
capture, credential capture, coherent banner and algorithm lists. Custom HTTP/HTTPS surface —
corporate portal, fake administrative paths, credential capture, JA4 and header-order capture.
Surface manifest and actuator reconciliation. Policies P0 and P1. Sandbox constructed with
authentication **closed**.

**Exit criterion.** Arm B live and demonstrably behaving differently from arm A on the same traffic.

**Deliverable.** SSH and HTTP surfaces; decision plane with P0/P1.
**Owner.** Eman Azam (SSH, decision plane), Uliya Fatima (HTTP, sandbox).

**Descope.** Off-the-shelf decoys for low-yield ports may be dropped entirely.

## 11.5 P3 — Interaction and intent

**Objective.** Open the post-authentication surface, which is where nearly all intent signal lives, and
bring intent inference online.

**Entry gate.** **All nineteen authentication-gate properties demonstrated** (§4.5). This gate is
binary and is not subject to schedule pressure.

**Work.** Authentication enabled into the restricted disposable shell. Stage-0 sinkhole egress
gateway with DNS proxy and instrumented responder. Session telemetry export. Circuit breaker and kill
switch with measured time-to-effect. Out-of-band intent inference with structured output. Policy P2.

**Exit criterion.** Arm C live; three-arm collection begins.

**Deliverable.** Interactive deception; intent model; complete three-arm system.
**Owner.** Uliya Fatima (sandbox, isolation, LLM), Eman Azam (egress gateway, decision plane).

**Descope.** If the gate cannot be passed, milestone 1 ships without post-authentication telemetry and
the intent model operates on pre-authentication signal only — see checkpoint C2.

## 11.6 P4 — Intelligence

**Objective.** Turn the collected corpus into something an analyst can act on, and make every session
reconstructable.

**Entry gate.** Three-arm collection running.

**Work.** ATT&CK technique mapping. **MITRE Engage activity mapping** on the deception side. Session
timelines. Actor profiles across linked addresses. Dashboards. Automated incident reports. IP
reputation and geolocation enrichment.

**Exit criterion.** An analyst can select any session and reconstruct it end to end — what arrived, what
was decided, what was exposed, what was attempted outbound, and why.

**Deliverable.** Intelligence plane. **Owner.** Sara Sultan.

**Descope.** In order: automated PDF reports, then Engage mapping, then reputation enrichment.

## 11.7 P5 — Evaluation

**Objective.** Produce the evidence for C3, and the write-up.

**Entry gate.** Pre-registration written *before* exposure began; at least four weeks of three-arm data.

**Work.** Scripted red-team profiles executed against all three arms. Human realism study. Survival
analysis of engagement. Detection-rate and intelligence-yield comparison. Cost accounting.
Milestone 1 write-up and demonstration.

**Exit criterion.** **Milestone 1 complete, demonstrable standalone**, with results reported against
the pre-registered analysis plan — including any null results.

**Deliverable.** Results, analysis, demonstration. **Owner.** Sara Sultan (statistics), whole team
(red team).

**Descope.** The human realism study before any part of the quantitative analysis.

## 11.8 P6 to P8 — Beyond milestone 1

**P6 Immersive environments.** L3 Immerse: richer generated filesystems, an internal network beyond the
first hop, credential material and canary tokens, and orchestration where pre-staging alone becomes
insufficient. This is where Kubernetes and sandboxing hardening return.

**P7 Learned policy.** Policy P3 trained on the corpus that P1, P2 and the three-arm study produce. The
action space is unchanged, which is what makes the corpus usable — a deliberate consequence of the
policy interface in §6.5.

**P8 Final evaluation and thesis.** Full evaluation across all policies, thesis, and defence.

\pagebreak

# 12. Prerequisites

Verified by a named person **before** the phase opens. A prerequisite that cannot be demonstrated is
not met.

## 12.1 P0 — Design and approval

| Category | Prerequisite |
|---|---|
| Approvals | Supervisor sign-off on accepting SSH authentication and on staged egress |
| Approvals | Provider terms of service confirmed for a passive deception host |
| Network | Exposure configuration chosen from the three options in §7.2 |
| Decision | **Objective taxonomy drafted** — the closed set of intents P2 conditions on |
| Inputs | This record, reviewed |

## 12.2 P1 — Sensing and ground truth

| Category | Prerequisite |
|---|---|
| Infrastructure | Server specification known; two VLANs separated; hypervisor management unreachable from the deception VLAN |
| Network | WireGuard dialled outbound and stable; exposure point reachable from the public internet |
| Software | Zeek with HASSH and JA4 support; append-only log storage with a disk-fill guard and retention policy |
| Skills | Zeek scripting; canonical event schema design; ECS field conventions |
| Inputs | Approvals from P0; exposure configuration decided |

## 12.3 P2 — Deception surfaces

| Category | Prerequisite |
|---|---|
| Skills | Python `asyncio`; `asyncssh`; **RFC 4253** SSH transport, sufficient to make banner and algorithm lists cohere |
| Skills | HTTP fingerprint surface — header ordering, TLS JA4, server-identity coherence |
| Software | Reference OpenSSH build identified, whose banner and algorithm lists the SSH surface will match exactly |
| Infrastructure | Sandbox host prepared with authentication closed |
| Inputs | Canonical event envelope frozen; A/A validation result available |

## 12.4 P3 — Interaction and intent

| Category | Prerequisite |
|---|---|
| **Gate** | **All nineteen authentication-gate properties demonstrated, not asserted** (§4.5) |
| Software | Sandbox runtime selected; egress gateway with DNS sinkhole and instrumented responder; kill switch with a measured time-to-effect |
| Accounts | LLM API access provisioned; local model host available if the server has ≥ 20 GB for Qwen3-30B-A3B |
| Skills | Linux namespaces, cgroups v2, seccomp; DNS sinkholing; structured LLM output with grammar-constrained decoding |
| Decision | Objective taxonomy **frozen** — P2 cannot be built against a moving taxonomy |
| Approvals | Written supervisor approval on file (gate item 19) |

## 12.5 P4 — Intelligence

| Category | Prerequisite |
|---|---|
| Skills | ECS schema; Elasticsearch data streams and index lifecycle management; Kibana |
| Skills | ATT&CK mapping methodology; MITRE Engage activity vocabulary |
| Software | Query layer deployed; ReportLab for report generation |
| Inputs | At least two weeks of three-arm data in the log |

## 12.6 P5 — Evaluation

| Category | Prerequisite |
|---|---|
| Skills | **Survival analysis** — Kaplan–Meier, log-rank, right-censoring |
| Inputs | **Pre-registration written before exposure began** — this cannot be retrofitted |
| Inputs | At least four weeks of three-arm data |
| People | Five participants recruited for the realism study |
| Software | Analysis environment able to replay the raw log end to end |

\pagebreak

# 13. Roadmap

## 13.1 Timeline

![Milestone 1 roadmap with phases, milestones and decision checkpoints](figures/f11-roadmap.svg)

| Week | Phase | Focus | Milestone |
|---|---|---|---|
| 0 | P0 | Approvals, exposure decision, procurement | — |
| 1 | P1 | Sensor plane, event log, observe-only exposure, A/A begins | **M1** First real event captured end to end |
| 2 | P1 | Actor linkage, taxonomy frozen, pre-registration written | **C1** A/A validation review |
| 3 | P2 | SSH and HTTP surfaces, decision plane, P0/P1 | **M2** Arm B live · **C2** Authentication gate review |
| 4 | P3 | Gate passed, shell enabled, sinkhole egress, intent inference, P2 | **M3** Arm C live, three arms collecting |
| 5 | P4 | ATT&CK and Engage mapping, timelines | — |
| 6 | P4 | Actor profiles, dashboards, reporting | **C3** Interactive-traffic sufficiency review |
| 7 | P5 | Red-team profiles, realism study, stage-1 egress if approved | — |
| 8 | P5 | Analysis, survival curves, write-up, demonstration | **M4** Milestone 1 demonstrable standalone |

## 13.2 Decision checkpoints

Each has a fallback agreed **in advance**, so that the decision on the day is a selection rather than
an improvisation.

**C1 — end of week 2. Is the A/A validation clean?**
If the exposure points receive materially different baseline traffic, the treatment comparison is
compromised before it starts. *Fallback:* switch to the time-sliced fallback configuration in §7.2 with
a balanced rotation, and record the observed exposure-point bias as a covariate in the analysis.

**C2 — end of week 3. Does the authentication gate pass?**
*Fallback:* milestone 1 ships without post-authentication telemetry. The intent model operates on
pre-authentication signal only — scan patterns, credential attempts, HTTP path exploration — and the
C-versus-B claim is narrowed to pre-authentication adaptation. The gate is never waived under schedule
pressure.

**C3 — end of week 6. Is there enough interactive-operator traffic for the C-versus-B comparison?**
*Fallback:* scale up the scripted red-team supplement, report the internet-derived result as
descriptive rather than inferential, and narrow the claim explicitly to the population actually
observed.

## 13.3 Descope order, agreed in advance

Removed in this order if time runs short:

1. Automated PDF incident reports
2. MITRE Engage mapping
3. Off-the-shelf decoys on low-yield ports
4. Human realism study
5. Stage-1 egress
6. **Arm C**

Arm C is last because removing it costs the contribution itself. Everything above it costs polish,
coverage or a secondary result.

## 13.4 Ownership

| Owner | Responsible for |
|---|---|
| **Eman Azam** | Sensor plane; egress gateway and host hardening; SSH deception surface; decision plane and policies |
| **Uliya Fatima** | Server and VLAN build; WireGuard; sandbox and isolation; HTTP deception surface; LLM integration |
| **Sara Sultan** | Event log and indexing; ATT&CK and Engage mapping; dashboards; reporting; evaluation statistics |

Assignments follow the expertise declared in the approved proposal, with two additions that no team
member has yet declared and which are flagged deliberately: **survival analysis** (§14, required at P5)
and **structured LLM output** (required at P3).

\pagebreak

# 14. Learning Plan and Resources

Organised the way an effective reading plan is: **what to read, when, and — more usefully — what to
skip.** Everything listed is freely available online except where noted as a book.

## 14.1 Shared, before week 1

| Resource | Why | Scope |
|---|---|---|
| **MITRE Engage** — `engage.mitre.org` | The adversary-engagement framework: a standard vocabulary for *deception activities*, the deliberate mirror of ATT&CK's vocabulary for adversary activities | Matrix, goals, approaches, activities. Roughly two hours |
| **MITRE ATT&CK Enterprise** — `attack.mitre.org` | Adversary-side mapping | **Only** Reconnaissance, Initial Access, Discovery, Credential Access, Execution, Persistence. The remainder waits for P4 |
| **Elastic Common Schema** | The canonical event envelope of §5.3 | Field reference for `source`, `destination`, `event`, `threat`, `user`. Skip the complete field list |
| The team's own bibliography | Already validated during FYP-1 | Re-read Sladić 2023, Wang 2024 and Rabzelj 2025 against the new design — each now reads differently |

> **A design addition surfaced while assembling this section.** Mapping deception *actions* to MITRE
> Engage alongside adversary actions to ATT&CK gives the intelligence plane a symmetric,
> standards-based vocabulary on both sides of the interaction. No open-source honeypot currently does
> this, it costs very little, and it strengthens the thesis materially. It is incorporated into the
> event envelope in §5.3 as `deception.engage_activity`.

## 14.2 Per person, per phase

| Owner | Phase | Learn | Skip |
|---|---|---|---|
| **Eman Azam** | P1 | Zeek scripting and the log framework; **nftables** — modern syntax, atomic sets and maps, not iptables | Suricata rule authoring; ET ruleset internals |
| | P2 | Python `asyncio`; `asyncssh`; **RFC 4253** SSH transport, enough to make banners and algorithm lists cohere | SSH key-exchange mathematics |
| | P3 | Linux namespaces, cgroups v2, seccomp; DNS sinkholing | Kubernetes networking — returns at P6 |
| **Uliya Fatima** | P1 | WireGuard; VLAN and bridge configuration; systemd service hardening | k3s and gVisor — return at P6 |
| | P2 | HTTP fingerprint surface: header ordering, TLS JA4, server-identity coherence | Web-framework depth beyond what the surface needs |
| | P3 | Sandbox isolation options and their escape surfaces; **structured LLM output** with grammar-constrained decoding | Model fine-tuning; prompt-engineering folklore |
| **Sara Sultan** | P1 | ECS field design; append-only log formats; disk-fill and retention control | Logstash grok — not in the data path |
| | P4 | Elasticsearch data streams and ILM; Kibana; ATT&CK and Engage mapping methodology; ReportLab | Wazuh — deferred |
| | P5 | **Survival analysis** — Kaplan–Meier, log-rank, right-censoring; the `lifelines` library | Cox proportional hazards unless covariates are wanted |

## 14.3 Deferred for milestone 1 — not dropped

Each deferred topic carries its resources and a **minimum useful slice**: the portion that makes the
topic usable, so it can be picked up in an evening rather than treated as a whole subject. Skipping
without resources means the topic can never be recovered; that is what this table prevents.

| Topic | Returns in | Resources | Minimum useful slice |
|---|---|---|---|
| **Kubernetes / k3s** | P6 | `docs.k3s.io`; kubernetes.io concept documentation; *Kubernetes Up & Running* (Burns, Beda, Hightower); the Kubernetes Python client documentation | Pods, Jobs, Namespaces, NetworkPolicy, resource limits. Skip Ingress, Helm, operators and StatefulSets |
| **gVisor** | P6 | `gvisor.dev` — "What is gVisor", the `runsc` runtime guide, the platform guide | Why syscall interception reduces escape risk, and how to set a RuntimeClass. **Note the gotcha:** gVisor identifies itself in `dmesg` output, which is an instant tell unless masked — exactly the class of detail that decides whether a deception survives contact |
| **Cowrie internals** | Reference only; not reintroduced as a component | `cowrie.readthedocs.io`; the GitHub source | Read its **logging schema** and its command-handler plugin architecture. Valuable as prior art and as a source of event-field ideas; not adopted, for the §9.3 doctrine reason |
| **Wazuh** | P4 optional, otherwise P6 | `documentation.wazuh.com` | Agent architecture, decoders and rules, file-integrity monitoring. Skip the compliance modules |
| **Logstash** | P6, if the proposal's pipeline diagram is wanted verbatim | Elastic's Logstash reference guide | `input` / `filter` / `output` structure, `grok`, and the `translate` filter — the last is how ATT&CK mapping is done declaratively |
| **Reinforcement learning** | P7 (policy P3) | Sutton & Barto, *Reinforcement Learning: An Introduction*, 2nd edition — free at `incompleteideas.net/book/the-book.html`; OpenAI *Spinning Up in Deep RL* for PPO; the team's own cited HoneyIoT paper (Guan et al. 2023) for the MDP framing | **Chapter 2 only** — multi-armed bandits. That is genuinely all policy P3 requires; full reinforcement learning is a distraction until the action space is much larger |
| **Remaining ATT&CK tactics** | P4 | `attack.mitre.org`; *MITRE ATT&CK: Design and Philosophy* (MITRE technical report, free); ATT&CK Navigator for heat maps | The Design and Philosophy paper explains *how* techniques are scoped, which is more useful than memorising them and is what makes your own mapping table defensible |
| **Survival analysis** *(required at P5 — listed here so it is not a surprise)* | P5 | The `lifelines` library documentation; Kleinbaum & Klein, *Survival Analysis: A Self-Learning Text*, chapters 1–3 | Kaplan–Meier curves, the log-rank test, and what right-censoring means. Cox regression only if covariates are wanted |

None of the above is required for anything on the milestone-1 critical path — that is what deferring
them means. They are listed so that studying early remains a choice rather than a blocked one.

## 14.4 Two skills nobody has declared

The expertise declared in the approved proposal covers containment internals, IDS tooling, Kubernetes,
the ELK stack, ATT&CK and reporting. Two requirements of this design fall outside all of it, and are
flagged here rather than discovered later:

**Survival analysis**, required at P5. Without it the central engagement result cannot be computed
correctly, because averaging censored durations produces a number that is confidently wrong rather
than obviously wrong. Two chapters and the `lifelines` documentation are sufficient.

**Structured LLM output**, required at P3. Arm C's manifests must be machine-comparable with arm B's,
which makes schema compliance a correctness property rather than a convenience. Grammar-constrained
decoding is the technique that makes it reliable.
