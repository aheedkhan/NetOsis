\part{PART I — DESIGN RECORD}

# 1. System Thesis

## 1.1 Identity

> **CyberSnare is an adaptive deception control plane that orchestrates, selects, monitors, and
> evolves deceptive environments based on observed adversary behaviour and inferred intent.**

Short form: **a controller for deception environments, not merely a honeypot.**

The noun is deliberate. Calling CyberSnare "a controller for honeypots" would make honeypots the
architecture; calling it a controller for *deception environments* leaves room for SSH surfaces, HTTP
surfaces, filesystems, credentials, network topology and generated documents to be selectable
capabilities rather than fixed products.

Every comparable system in the literature — Cowrie, T-Pot, OpenCanary, HoneyGPT — is fundamentally a
*server*. It listens, it responds, it writes logs. Its behaviour is decided at configuration time and
does not change in response to who is on the other end. CyberSnare sits one level above that layer.
The servers become interchangeable **actuators**, and the interesting engineering moves into deciding
which of them to expose, populated with what, to whom, and when.

## 1.2 The four planes

![The four planes and the feedback edge that closes the loop](figures/f01-four-planes.svg)

| Plane | Responsibility | Must not |
|---|---|---|
| **Sensor** | Observe. Produce normalised evidence from network and host sources | Make decisions, or be addressable from the deception zone |
| **Decision** | Maintain belief about the adversary; select capabilities; emit a manifest | Touch the network directly, or terminate attacker connections |
| **Deception** | Present the selected capabilities; capture interaction telemetry | Hold state that the decision plane owns, or route its own egress |
| **Intelligence** | Correlate, map, profile, report | Sit in the fast path of any decision |

The separation is not tidiness for its own sake. It is what makes §7's experiment possible: the policy
inside the decision plane can be swapped between three implementations while sensors and actuators
stay byte-identical, so the only difference between experimental arms is the variable under test.

## 1.3 Deception as a feedback control system

Stating the architecture as a control system rather than a pipeline is a design choice with concrete
consequences.

```
   SENSOR ──────► DECISION ──────► DECEPTION ──────► (adversary)
   plane          plane            plane                 │
     ▲                                                   │
     └───────────────── feedback ────────────────────────┘
                            │
                            ▼
                      INTELLIGENCE plane
```

A pipeline has a beginning and an end and is judged on throughput. A control system has a *loop*, and
is judged on whether the loop closes fast enough to affect the thing it is controlling. That framing
gives us:

- **A stated loop period**, and therefore a latency budget that can be violated and measured (§6.4).
- **A separable policy.** In control terms the estimator and the controller are different components;
  in ours, belief estimation and capability selection are different components, and the second can be
  replaced without disturbing the first.
- **An honest failure mode.** If the loop is slower than the adversary's reconnect interval, the
  system is not "a bit laggy" — it is open-loop, and every adaptive claim made about it is void. This
  is precisely the failure the original provisioning design would have suffered.

![End-to-end data flow, showing the fast path that closes the control loop and the slow path that feeds analysis](figures/f02-data-flow.svg)

The two paths in Figure 2 are the practical expression of the same idea. The **fast path** carries only
what a decision needs and never traverses a datastore. The **slow path** carries everything, tolerates
seconds or minutes of delay, and feeds the intelligence plane. Collapsing them into one — as the
original design did, routing all sources through a SIEM before analysis — is what makes a deception
system open-loop without anyone noticing.

\pagebreak

# 2. Novelty Claim

## 2.1 The claim

> **An intent-conditioned deception control plane that selects and adapts exposed deception
> capabilities according to inferred adversary objective, using behavioural scoring as evidence rather
> than as the sole escalation criterion.**

The control-plane architecture and intent-conditioned selection are presented as **one combined
contribution**, not two. Separating them would weaken both: the architecture alone reads as good
separation of concerns, and intent conditioning alone has nowhere to live.

## 2.2 The conceptual jump

![Decision flow: scoring becomes evidence feeding intent inference, not the verdict itself](figures/f03-decision-flow.svg)

```
  Traditional adaptive honeypot          CyberSnare
  ───────────────────────────            ──────────────────────────────
  activity                               behavioural evidence
     ↓                                      ↓
  score = 73                             scoring / features ──┐
     ↓                                      ↓                 ↓
  Tier 3                                 intent inference    confidence
                                            └───────┬─────────┘
                                                    ↓
                                             CONTROL PLANE
                                    select deception capabilities
                                                    ↓
                                            DECEPTION ENVIRONMENT
```

Every adaptive honeypot in the surveyed literature escalates on a scalar. Behaviour produces a number,
the number crosses a threshold, a fixed next stage is presented. What is missing is any notion of
*what the adversary appears to be trying to achieve* — and therefore any ability to present deception
that is relevant rather than merely deeper.

An adversary enumerating SSH keys and probing `sudo` wants something different from one downloading a
mining binary. A scalar cannot distinguish them; both simply score highly. An intent model can, and a
control plane conditioned on it can present a credential-rich environment to the first and a
permissive execution environment to the second.

## 2.3 Phrasing discipline

There is a version of this claim that is much easier to attack, and it must be avoided:

> ~~"CyberSnare replaces behavioural scoring with AI intent detection."~~

That sentence abandons approved objective O1, invites the question of why the approved design was
discarded, and stakes everything on the AI component working. The correct framing:

> **CyberSnare uses behavioural scoring as one source of evidence inside an intent-conditioned control
> plane.**

The score becomes evidence, not the verdict. O1 is satisfied rather than replaced, and the system
degrades gracefully: if intent inference is unavailable, the control plane still has scoring-based
policy P1 to fall back on.

## 2.4 Contributions

| | Contribution | Type |
|---|---|---|
| **C1** | Intent-conditioned deception control plane | System |
| **C2** | Capability and environment selection driven by inferred adversary objective | Mechanism |
| **C3** | Controlled evaluation isolating adaptation from AI-generated realism | Evidence |

C3 is the evidence that validates or falsifies C1 and C2. It is **not** the primary novelty claim.
Positioning it as the headline would turn a systems project into a research-methods project.

## 2.5 What is explicitly not claimed as novel

Stating these first, in the document and in the defence, removes the examiner's best line of attack.

| Not novel | Prior art | The difference |
|---|---|---|
| Honeypots | Spitzner 2003; Mokube & Adams 2007 | We do not claim the concept |
| Multi-tier / dynamic honeypots | Kuwatly et al. 2004; Hegedüs et al. 2024 | They escalate on scalars; we condition on inferred objective |
| LLM-generated honeypot responses | Sladić et al. 2023; Wang et al. 2024 (HoneyGPT) | They put the model in the response path; we bar it from the request path and use it for inference |
| ML classification of attackers | Franco et al. 2022; Lanz et al. 2025 | Classification is an input to our belief state, not the output of the system |
| ATT&CK mapping | Wang & Lu 2018 and commercial platforms | We add the deception-side mapping (MITRE Engage), which is the part that is uncommon |
| Containerised honeypot farms | T-Pot | Orchestration is an implementation detail beneath the control plane, not the contribution |

\pagebreak

# 3. Milestone 1 Boundary

## 3.1 In scope

| Area | Delivered |
|---|---|
| Sensor plane | Zeek with HASSH and JA4 extraction (required); Suricata as an enricher for tool labelling |
| Deception surfaces | Custom Python `asyncio` SSH and HTTP surfaces; off-the-shelf decoys for low-yield ports |
| Interaction | **Successful SSH authentication into a real but highly restricted, disposable shell**, so post-authentication behaviour becomes a primary intent signal |
| Decision plane | Belief state; policies P0 (static), P1 (score-based), P2 (intent-conditioned); manifest reconciliation |
| Telemetry | Canonical event envelope; append-only log as system of record; actor identity linkage |
| Intelligence | ATT&CK and Engage mapping; session timelines; actor profiles; incident reporting |
| Safety | Instrumented egress gateway at stage 0 (sinkhole); the nineteen-property authentication gate |
| Evaluation | Three-arm harness with A/A validation and pre-registration |

## 3.2 Designed here, built later

Kubernetes orchestration. Distinct Tier 2 and Tier 3 environments as separate infrastructure. Learned
policy P3. Full-scale artifact generation. eBPF syscall telemetry. Wazuh. Logstash. Stage-2 egress.

Each is specified sufficiently in this record that it can be built without redesign, and each is
mapped to the phase that introduces it in §11.

## 3.3 The standing requirement

> **Milestone 1 must stand alone** — demonstrable, defensible and publishable even if nothing further
> is built.

This is not a hedge against failure; it is a design constraint. It forces every component in §3.1 to
be independently useful, and it means the thin slice built in week 1 must be a complete vertical
through all four planes rather than a horizontal layer waiting for the others.

\pagebreak

# 4. Security Boundary

## 4.1 The principle

> **The attacker may have internet access, but the attacker never controls the path to the internet.**
>
> No direct route exists from sandbox to internet. All external connectivity traverses an isolated,
> monitored egress gateway with explicit policy enforcement and complete telemetry.

An earlier draft of this design made "no egress, ever" a safety absolute. That was wrong, and the
reason is worth recording because it inverts the usual security instinct: **denying egress discards
half the evidence.** What a compromised environment *tries to contact* — the domains it resolves, the
ports it opens, the payloads it reaches for — is a second, independent stream of intent evidence, and
unlike host telemetry it cannot be faked by an adversary who suspects they are being watched.

Granting egress is therefore a *research* decision, not a convenience. The engineering problem is to
grant it without ever handing over control of the path.

## 4.2 Topology

![The security boundary: egress gateway, passive monitoring, and the deception zone](figures/f04-security-boundary.svg)

Three properties of Figure 4 are load-bearing:

1. **The egress gateway is the only route out.** The deception zone has no default route of its own.
2. **The monitoring plane holds no address in the deception VLAN.** It is a passive tap or an L2
   bridge. An inline L3 hop would be visible to the adversary and therefore attackable — a monitoring
   system that can be attacked is not a monitoring system.
3. **Analysis tooling lives on the analyst side.** Zeek, Suricata and `tcpdump` run outside the
   sandbox; Wireshark is a viewing layer over exported captures and is never an attacker-side
   component.

## 4.3 Staged egress

Open egress is how honeypots become botnet members, cryptocurrency miners and outbound scanners.
Logging that happening documents it; it does not prevent it. But the observation that rescues the
design is this: **most of the intelligence value is in what the adversary tried to reach, not in the
bytes that come back.**

| Stage | Behaviour | Risk | Approval |
|---|---|---|---|
| **0 — Sinkhole** *(default from day one)* | DNS resolves to the gateway; HTTP and HTTPS are served by an instrumented responder. `wget http://evil/x.sh` **appears to succeed** and never touches the real internet. Captures the query, the full URL, the user-agent, retry behaviour and the intended payload name | **Zero** | None required |
| **1 — Allowlisted real fetch** | DNS and HTTP/HTTPS `GET` only, rate-limited and byte-capped. The gateway fetches out of band for analysis and may serve a neutered response — malware *collection* without malware *execution* | Low | Supervisor sign-off |
| **2 — Policy-bounded real egress** | Real outbound under the policy table in §4.4 | Real | Written supervisor and provider approval; full gate; tested kill switch |

Milestone 1 ships stage 0 and is designed for stage 1. Stage 2 is a separate, later decision and is
not required for any claim made in this record.

## 4.4 Egress policy for stages 1 and 2

Default-deny with an allowlist. Not log-and-allow.

| Traffic | Policy |
|---|---|
| DNS | ALLOW via gateway resolver, LOG |
| HTTP / HTTPS | ALLOW, LOG, rate-limit, byte-cap |
| ICMP | Controlled |
| **All other TCP / UDP** | **DENY by default**; allowlist only |
| SMTP | DENY |
| RFC1918 — 10/8, 172.16/12, 192.168/16 | DENY |
| Host IP, hypervisor management, container runtime socket, orchestrator API | DENY |
| Management VLAN, VPN and tunnel endpoints, monitoring plane | DENY |

The single line that must not survive from any earlier design is *"arbitrary TCP: log and allow."*
Outbound SSH, SMB and RDP scanning is the most common abuse originating from a compromised honeypot,
and it is precisely what an allow-and-log rule permits.

## 4.5 The SSH authentication gate

Authentication into the shell cannot be enabled until every property below is **demonstrated**, not
asserted. Items marked ★ were added during design review beyond the original twelve.

| # | Property |
|---|---|
| 1 | No direct internet route from sandbox |
| 2 | Controlled egress only |
| 3 | No host-management access |
| 4 | No container-runtime socket |
| 5 | No access to other attacker sessions |
| 6 | CPU, memory and process limits enforced |
| 7 | Filesystem isolation |
| 8 | Ephemeral reset between sessions |
| 9 | Audit logging exported outside the sandbox |
| 10 | Escape-attempt detection |
| 11 | Automatic teardown |
| 12 | Management plane unreachable from attacker |
| 13 ★ | Monitoring plane holds no IP address in the deception VLAN |
| 14 ★ | Egress is default-DENY allowlist, not log-and-allow |
| 15 ★ | Outbound connection-rate circuit breaker with automatic teardown |
| 16 ★ | Sandbox cannot reach VPN/tunnel endpoints or the second VLAN |
| 17 ★ | Kill switch tested, with a measured time-to-effect |
| 18 ★ | Egress attribution verified — attacker-initiated traffic provably exits via the disposable front-end |
| 19 ★ | Written supervisor approval on file |

## 4.6 Containment is an invariant

Containment is a **global property holding at every deception level**, never a state that is escalated
into. The original design activated containment when a behavioural score reached 75, which would leave
egress unconstrained during precisely the window in which an adversary is most active. This is
recorded as a genuine safety defect rather than a design preference, and is the one change in this
record that would have been necessary regardless of any other consideration.

\pagebreak

# 5. Telemetry Model

## 5.1 Two independent evidence streams

![Host-session and network telemetry converging on the behaviour engine](figures/f05-evidence-streams.svg)

The correlation of these two streams is what makes intent inference materially better than either
alone, and it is the strongest justification for granting egress at all. An adversary can moderate
what they type. They have far less control over what their tooling resolves, connects to, and
transfers.

## 5.2 Sources

| Source | Plane | Provides |
|---|---|---|
| Deception surfaces (SSH, HTTP) | Deception | Authentication attempts, credentials, requests, client fingerprints |
| Sandbox session telemetry | Deception | Commands, files accessed, processes, privilege attempts |
| **Zeek** *(required)* | Sensor | Connection records, DNS, HTTP, TLS, **HASSH**, **JA4** |
| Suricata *(enricher)* | Sensor | Signature alerts, tool labels from the ET ruleset |
| Egress gateway | Sensor | Outbound DNS, connection metadata, policy decisions, packet capture |

Zeek is required because the client fingerprints it produces are load-bearing for identity linkage
(§5.5) and nothing else supplies them as cheaply. Suricata is deliberately **demoted from a decision
source to an enricher**: signature alerts are excellent for labelling known tooling and poor as a basis
for behavioural inference.

## 5.3 One canonical event envelope

Every source normalises into a single event schema, aligned to Elastic Common Schema where ECS has a
suitable field. This envelope is the integration contract of the entire system and is frozen before
any service is written.

```
{
  "@timestamp": "...",
  "event":       { "kind", "category", "action", "dataset" },
  "session":     { "id", "actor_key", "arm", "level" },
  "source":      { "ip", "port", "geo", "as" },
  "destination": { "ip", "port", "service" },
  "network":     { "hassh", "ja4", "ua_signature" },
  "user":        { "name" },
  "threat":      { "technique": {"id","name"}, "tactic": {"id","name"} },
  "deception":   { "capability", "manifest_id", "engage_activity" },
  "cybersnare":  { "score_delta", "intent", "confidence", "suspicion", "novelty" }
}
```

The `deception.engage_activity` field is where MITRE Engage identifiers are recorded. Carrying both
ATT&CK (what the adversary did) and Engage (what we did in response) in the same envelope gives the
intelligence plane a standards-based vocabulary on both sides of the interaction.

## 5.4 The append-only log is the system of record

> The **append-only JSONL event log on disk is the system of record.** Elasticsearch, Kibana or DuckDB
> are a query and visualisation layer *over* that log, never the pipeline itself.

For a research system this matters more than a dashboard. Analysis code will contain bugs; mapping
tables will be revised; metric definitions will change after the first look at real data. With the raw
log as the source of truth, every one of those revisions is a re-run. With a datastore as the pipeline,
each one is a partial and irreversible loss of the dataset.

It also has three practical consequences: the format has no dependencies and cannot fail to start;
replay makes the whole system testable offline against recorded traffic; and if the server turns out
to be smaller than hoped, Elasticsearch can be dropped entirely without touching the data path.

## 5.5 Identity: actors, not addresses

Identity keys on a linked **actor**, not on a source IP.

| Signal | Source | Links across |
|---|---|---|
| HASSH | Zeek | SSH client implementations and versions |
| JA4 | Zeek | TLS client stacks |
| User-agent and header ordering | HTTP surface | HTTP tooling |
| Credential-pair reuse | SSH / HTTP surfaces | Campaigns sharing a wordlist |
| Timing signature | Derived | Automation cadence |

Per-IP identity fails in both directions: a single adversary rotating addresses fragments into many
apparent actors, and carrier-grade NAT collapses many actors into one address. Actor linkage carries a
`linkage_confidence` and is itself evidence rather than ground truth.

## 5.6 Fast path and slow path

| Path | Budget | Carries | Traverses a datastore |
|---|---|---|---|
| Fast | < 100 ms | Only what a decision needs | **No** |
| Slow | seconds to minutes | Everything | Yes |

## 5.7 Retention and handling

Captured credentials and payload bytes are sensitive, and adversaries do sometimes submit real
credentials harvested elsewhere. They are retained deliberately — the credential corpus is a genuine
research output — under access restriction, a bounded retention period, a no-republication rule, and
the inference-routing constraint in §6.6.

\pagebreak

# 6. Intent and Adaptation Model

## 6.1 Decision flow

```
telemetry → behavioural evidence → scoring / features → intent inference → confidence
          → deception capability selection
```

Behavioural scoring is **evidence, not the final decision**. This single sentence is the difference
between the approved design and this one, and it is what §2.3 protects.

## 6.2 Belief state

Maintained per adversary, not per connection or per address.

```
Adversary {
  identity   : actor_key, linked_ips[], {hassh, ja4, ua_signature}, linkage_confidence
  capability : automated | scripted | interactive_operator
  intent     : probability distribution over objectives
  engagement : depth, duration, novelty
  suspicion  : P(adversary believes this is a deception)
  posture    : current level + which capabilities are exposed
}
```

Two variables go beyond the approved model, and both earn their place:

**`suspicion`** — the probability that we are blown. It is this, not a threat score, that should govern
whether to escalate or withdraw, and it is measurable: fingerprinting probes, `/proc` and `dmesg`
reads, checks for virtualisation artifacts, abrupt disconnection after a specific command, timing
analysis. Nothing in the surveyed literature models it explicitly, and it is what research question
RQ2 is actually asking about.

**`novelty`** — how much genuinely new information the current session is still yielding. This is the
resource-allocation signal that turns "don't waste deception on a commodity scanner" from an intuition
into a computable quantity.

## 6.3 Capabilities, not tiers

The three-tier concept remains part of the research identity and the thesis vocabulary. Internally,
deception is modelled as **selectable capabilities and states**, so escalation does not imply
provisioning new infrastructure.

**Action space:**

`observe` · `open(capability)` · `close(capability)` · `populate(capability, bundle)` · `delay(ms)` ·
`burn` · `block`

The policy emits a declarative **deception surface manifest**; the actuator's only job is to converge
reality toward it.

![Belief state to manifest to actuator reconciliation](figures/f06-capability-selection.svg)

**Levels and terminals:**

![Session lifecycle across deception levels, with BURN and BLOCK terminals](figures/f07-session-lifecycle.svg)

| State | Meaning |
|---|---|
| **L0 Observe** | Sensing only. No response beyond what an unremarkable host would give |
| **L1 Attract** | Deception surfaces exposed; authentication refused |
| **L2 Engage** | Authentication succeeds; restricted shell; populated filesystem |
| **L3 Immerse** | Richer environment, internal network, credential material *(designed, built post-milestone-1)* |
| **BURN** | Suspicion high. Stop spending, harvest what is available, disengage |
| **BLOCK** | Safety or abuse response |

`BURN` deserves emphasis because it has no analogue in the surveyed literature. Every published
adaptive honeypot escalates monotonically. Recognising that a deception has been detected and
deliberately *withdrawing* — rather than continuing to spend resources on an adversary who is now
merely enumerating your honeypot's tells — is a direct consequence of modelling suspicion.

## 6.4 Deception latency — the frozen constraint

The proposal's own literature review cites an average SSH session of **eight commands in twenty-nine
seconds**. Therefore:

| Stage | Budget |
|---|---|
| Decision | **< 100 ms** |
| Actuation of an already-staged capability | **< 1 s** |
| Anything requiring materialisation | **> 1 s — must be pre-staged or lazily materialised** |

This is the number that invalidates provision-on-escalation, and it belongs on the first page of any
architecture document that follows this record. A control loop slower than the process it controls is
not a slow control loop; it is an open loop.

## 6.5 Policies

| | Policy | Description | Role |
|---|---|---|---|
| **P0** | Static | Identical capabilities always exposed | Control arm |
| **P1** | Utility-maximising | `argmax_a  E[intel_gain \| belief, a] − λ·cost(a) − μ·P(blown \| belief, a)` | Adaptive, score-based, no AI |
| **P2** | Intent-conditioned | Manifest selected from the inferred objective distribution | **The contribution** |
| **P3** | Learned | Bandit or RL over the same action space, trained on the corpus P1 and P2 collect | Future work, honestly labelled |

P1 is explicitly decision-theoretic rather than threshold-based, which means it is auditable — for any
action taken, the expected gain, the cost and the estimated risk of being detected can all be shown.
It also requires no training data, which is what makes it a viable arm from week 3.

## 6.6 What the AI does

> **The AI's job is inference and planning — never impersonation.**

| Path | Budget | What runs |
|---|---|---|
| **Fast** — attacker request path | < 100 ms | Deterministic features only. **No LLM, ever** |
| **Slow** — out of band, per session | seconds | LLM reads the normalised transcript *and* correlated network telemetry, and emits `{objective, confidence, predicted_next_actions, recommended_manifest, rationale}` |
| **Offline** — pre-deployment | minutes | Persona and artifact bundle generation, plus consistency validation |

Three reasons the model is barred from the request path, in order of severity. **Nondeterminism**: ask
the same question twice and receive two different answers — a tell no amount of prompt engineering
removes. **Latency** an adversary can feel. And **prior art**: LLM-in-the-response-path is exactly what
Sladić et al. and HoneyGPT already published, so it is the one place where the design cannot claim
novelty anyway.

Keeping inference out of band has a further benefit worth stating: an API outage degrades adaptation
quality rather than availability. The deception keeps working; it just stops getting smarter.

The `rationale` string is **explainability**. It goes directly into the incident report, and it is what
keeps arm C comparable to arm B — both emit manifests in the same typed space, differing only in who
chose them.

## 6.7 Model routing by data sensitivity

| Data class | Route |
|---|---|
| Transcripts containing captured credentials, payload bytes, or personal data | **Local model only** — never leaves the machine |
| Everything else | Hosted API permitted |

This is a data-governance rule for the ethics chapter, not a cost optimisation.

**Hosted primary: Claude API**, chosen for structured-output reliability — which matters more here
than raw capability, because arm C's manifests must be machine-comparable with arm B's.

**Local: Qwen3-30B-A3B-Instruct**, Q4_K_M, roughly 18–20 GB, with only 3 B parameters active per token
and therefore fast on modest hardware. With **grammar-constrained decoding**, a local model can achieve
*better* schema compliance than a hosted API — an inversion of the expected trade-off that is worth
stating explicitly, because it means the privacy-preserving route is not the weaker route.

The interface is provider-agnostic. Week 4 benchmarks Claude, Qwen3 and GLM against a golden set on
structured-output validity, agreement with human intent labels, latency and cost.

\pagebreak

# 7. Experimental Design

## 7.1 Three arms

![A/A validation, then three-arm treatment with weekly rotation](figures/f08-experiment-design.svg)

| Arm | Configuration | Answers |
|---|---|---|
| **A** | Static — off-the-shelf, no adaptation | Baseline |
| **B** | Adaptive, score-based policy P1, no AI | **RQ1 — does adaptation work?** (B vs A) |
| **C** | Adaptive, intent-conditioned P2 with AI realism | **RQ2 — does intent conditioning and AI realism add value?** (C vs B) |

The three-way split is what allows the thesis to say *which component actually matters*. A two-arm
design comparing "CyberSnare" against "a static honeypot" can only report that the whole bundle helped,
which is the weakest possible finding. A null result on C versus B remains a genuine, publishable
contribution: it would say that adaptation carries the benefit and generated realism does not.

## 7.2 Exposure configuration — preferred, not assumed

Three **independently addressable public exposure points** are the preferred configuration. **None have
been purchased.** Different ports are explicitly rejected as the primary separation, because adversaries
scan ports non-uniformly and the arms would differ in traffic before any treatment applied.

![Exposure options: preferred, alternative and fallback](figures/f09-exposure-options.svg)

| | Option | Status |
|---|---|---|
| **Preferred** | Three public IPs, same provider and subnet, on a rented front-end tunnelled back to the lab server | Requires a purchase decision |
| **Alternative** | DMZ address and inbound DNAT requested from the university network administrator | Requires an admin request; feasibility unknown |
| **Fallback** | Single exposure point with **time-sliced arms** on a balanced rotation — a Latin square across time-of-day and day-of-week | Always available; weaker, since traffic populations vary by hour and weekday, but analysable when properly balanced |

Two constraints hold regardless of which option is chosen.

**Arms must share a provider and subnet.** Different autonomous systems carry different reputations and
scanning histories, which would confound the comparison more severely than the treatment affects it.

**WireGuard dialled outbound from the lab server requires no inbound firewall rule.** This matters
because the team has no firewall access. Any front-end option is therefore reachable without an
administrator request on the critical path, and routing sandbox egress back through that same tunnel
places attribution for attacker-initiated traffic on a disposable rented machine rather than on a
university address.

## 7.3 Validity controls

**A/A validation before any treatment.** All exposure points run identical configurations for the first
two weeks, testing whether they receive materially different baseline traffic. This quantifies
exposure-point bias before any claim rests on the comparison. It is the difference between a result and
an anecdote, and it costs nothing but calendar time that is being spent on construction anyway.

**Weekly rotation of arm to exposure point**, cancelling per-address reputation and scan-history
effects that accumulate over the study period.

**Assignment by actor, not by connection**, once identity is established. Arm-switch events — which
occur when actor linkage merges two previously separate identities — are recorded and censored rather
than silently mixed.

**Pre-registration** of hypotheses, metrics and the analysis plan, written before exposure begins. It
costs nothing, prevents post-hoc metric selection, and is unusual enough at this level to be noticed
favourably.

## 7.4 Analysis

Engagement duration is **time-to-event data with right-censoring**. Sessions that have not ended when
observation stops, and adversaries who never detect the deception, are censored observations — not
missing data, and not values that can be averaged.

| Analysis | Method |
|---|---|
| Engagement duration across arms | Kaplan–Meier estimator, log-rank test |
| With covariates (capability class, tooling, geography) | Cox proportional hazards |
| Count outcomes (commands, techniques, credentials) | Negative binomial regression |
| Detection rate | Proportion with exact confidence intervals |

The composite formula in the original proposal — engagement duration × escalation depth ÷ detection
time — is dropped rather than repaired. It is undefined when the adversary never detects the
deception, which will be the majority of cases, and it conflates quantities with different units and
different variances into a number that cannot be tested for significance.

## 7.5 Metrics

Measured separately, never composited into a single score.

| Family | Metrics |
|---|---|
| **Engagement** | Time to disconnect · commands issued · requests made · interaction depth · level reached |
| **Intelligence** | Unique behaviours · tools identified · ATT&CK techniques observed · credentials captured · files accessed · lateral-movement attempts · objective inferred |
| **Deception** | Detection rate · fingerprinting attempts · time-to-detection · false deception triggers |
| **Adaptation** | Decision latency · actuation latency · materialisation latency · resource consumption |
| **Safety** | Outbound attempts blocked · escape attempts · cross-session visibility · resource-exhaustion attempts |
| **Cost** | Compute and API spend per unit of intelligence |

Cost is included because it is what makes adaptation worth doing at all — a system that triples
engagement at ten times the cost per session has not obviously improved anything — and because it is
trivially measurable.

## 7.6 The largest threat to validity

**Live internet traffic is overwhelmingly automated.** Interactive human operators may appear only a
handful of times across eight weeks, and they are precisely the population the adaptive machinery
exists to serve. The comparison most central to the thesis is therefore the one with the least data.

Stated mitigations: the scripted red-team profiles supplement the human sample under controlled
conditions; the exposure window is made as long as construction allows; and accepting SSH
authentication makes the target materially more attractive to human follow-up than a refusing decoy
would be. If checkpoint C3 (§13) finds the interactive sample insufficient, the claim is narrowed
explicitly rather than defended on underpowered data.

\pagebreak

# 8. Unresolved Decisions

Each item names what it blocks and when it must be resolved. Nothing in this record assumes any of
them has been settled.

| # | Decision | Blocks | Due |
|---|---|---|---|
| 1 | **Exposure configuration** — purchase three IPs, request a DMZ address, or accept the time-sliced fallback | Experiment design (§7.2) | Week 0 |
| 2 | **Server specification** — currently unknown. Local Qwen3-30B-A3B needs ~20 GB. Without it, inference is API-only and the routing rule in §6.7 tightens to *credentials and payloads are never sent for inference at all* | AI routing | Week 4 |
| 3 | **Written supervisor approval** for accepting SSH authentication and for staged egress | Authentication gate item 19 | Week 4 |
| 4 | **Provider terms of service** confirmation for a passive deception host | Exposure | Week 0 |
| 5 | **Stage 1 / stage 2 egress** go or no-go | Egress policy | Week 7 |
| 6 | **Internal network at L3 Immerse** — how much is real and how much simulated | Milestone 2 design | Post-milestone-1 |
| 7 | **Objective taxonomy** — the closed set of intents the model infers over, which determines what P2 can condition on and what the metrics can measure | Pre-registration, and therefore all of §7 | **Week 2** |

Item 7 deserves particular attention. It is the least visible of the seven and the most constraining:
the set of objectives P2 can condition on defines the ceiling of what "intent-conditioned" can mean,
and once pre-registration is written it cannot be revised without weakening the analysis.

\pagebreak

# 9. Proposal to Engineering Deltas

## 9.1 Preserved — every approved objective is satisfied

| Proposal | Realised as |
|---|---|
| **O1** Behavioural scoring engine | **Retained as a component.** One evidence source feeding the belief state, rather than the escalation verdict |
| **O2** Three-tier escalation architecture | Research identity retained; internally modelled as selectable capabilities and states |
| **O3** Kubernetes orchestration | Actuator plane with pre-staged capabilities; orchestration used where it earns its place, not everywhere |
| **O4** AI artifact generation | AI performs inference and planning, plus offline artifact synthesis |
| **O5** Dynamic containment | Global safety invariant plus the instrumented egress gateway — **stronger** than the original, which only blocked |
| **O6** SIEM and intelligence pipeline | Intelligence plane over the append-only log; Elasticsearch and Kibana as a query layer |
| **O7** Evaluation across attacker profiles | Three-arm controlled experiment with per-profile breakdown |
| **RQ1** | Arm B versus arm A |
| **RQ2** | Arm C versus arm B |
| **RQ3** | Actuation latency and resource metrics against the deception-latency budget |
| **RQ4** | Per-profile breakdown across all three arms |

## 9.2 Not inherited — each requires independent justification before it may return

| Element | Status and reason |
|---|---|
| Scalar thresholds 25 / 50 / 75 | **Dropped.** Score is evidence; thresholds are not the decision |
| Weights +5 / +10 / +15 / +20 / +25 / +30 / +40 | **Dropped.** Arbitrary, unvalidated, and untunable without a decay model |
| Seven controller states | **Dropped.** Replaced by four levels and two terminals, derived from the action space rather than enumerated in advance |
| Redis as state store | **Dropped.** Solves a shared-state problem this architecture does not have; the decision plane owns state and rebuilds from the log |
| Per-IP attacker identity | **Dropped.** Replaced by actor linkage across addresses (§5.5) |
| ELK as the data path | **Dropped.** The append-only log is the system of record; ELK is a query layer |
| `duration × depth ÷ detection_time` | **Dropped.** Undefined under censoring; replaced by survival analysis |
| Provision-on-escalation | **Dropped.** Violates the deception-latency budget (§6.4) |
| Cowrie as the Tier 2 core | **Dropped.** It simulates a probeable surface, which is why it is fingerprinted — a conclusion drawn from the project's own literature review |
| Containment activated at score 75 | **Dropped.** Safety defect; containment is invariant (§4.6) |
| Suricata as a decision source | **Demoted** to enricher; Zeek is the required sensor (§5.2) |

## 9.3 The design doctrine behind the drops

Several of the decisions above follow from one principle, recorded here because it resolves future
real-versus-simulated questions mechanically rather than case by case:

> **Be real wherever the adversary can run an unbounded probe. Simulate only what they can read.**

The probe space of an executable surface cannot be enumerated, so any simulation of it is eventually
caught. The probe space of a readable surface *can* be enumerated, so it can be pre-validated for
consistency.

| Surface | Decision | Reason |
|---|---|---|
| TCP, TLS, SSH cryptography | **Real** | Trivially probed; requires matching algorithm lists |
| Banners, headers, versions | Simulated, **coherent** | Must agree with the claimed build — mismatched key-exchange lists are the classic tell |
| Authentication logic | Real logic, chosen outcome | Must remain consistent across reconnections |
| **Shell and command execution** | **Real, in a disposable sandbox** | Unbounded probe space; emulation always loses here |
| Filesystem contents | **Simulated, pre-generated** | Bounded and pre-validatable — this is where AI belongs |
| Internal network | First hop real, beyond it simulated | Adversaries rarely pivot far before the evidence is sufficient |
| Egress to internet | **Real, never attacker-controlled** | §4 |
| Time — timestamps, uptime, log ages | Simulated, coherent | Cheapest realism gain, and the most commonly botched |

This doctrine is why Cowrie is dropped rather than merely deprecated, and why the tier ladder
collapses: if a shell is granted at all it should be genuine from the first second, and what varies
between levels is the filesystem and the surrounding network, not whether the shell is real.
