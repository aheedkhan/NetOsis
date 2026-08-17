\part{APPENDICES}

# Appendix A. Glossary

| Term | Meaning in this document |
|---|---|
| **Actor** | A linked adversary identity spanning one or more source addresses, established by fingerprint and behavioural linkage rather than by IP |
| **A/A validation** | Running all experimental arms with identical configuration to test whether the exposure points themselves differ, before any treatment is applied |
| **Belief state** | The decision plane's running model of an actor: identity, capability, intent, engagement, suspicion, posture |
| **BURN** | Terminal state entered when suspicion is high: stop spending, harvest remaining evidence, allow disengagement |
| **Capability** | An individually selectable element of deception — a service, a filesystem, a credential set, a network hop |
| **Censoring (right-)** | An observation whose end was not seen — a session still running at cutoff, or an adversary who never detected the deception |
| **Control plane** | The decision-making layer that selects what deception to expose, as distinct from the deception itself |
| **Deception latency** | The time from evidence arriving to the corresponding change being live on the deception surface |
| **ECS** | Elastic Common Schema — the field-naming convention the canonical event envelope aligns to |
| **HASSH** | A fingerprint of an SSH client derived from its offered algorithm lists; links sessions across addresses |
| **JA4** | A fingerprint of a TLS client stack; the successor to JA3 |
| **Manifest** | A declarative statement of which capabilities should be exposed to a given actor; the actuator converges reality toward it |
| **MITRE ATT&CK** | Standard taxonomy of adversary tactics and techniques |
| **MITRE Engage** | Standard taxonomy of *defender* adversary-engagement and deception activities |
| **Novelty** | How much new information a session is still yielding; the resource-allocation signal |
| **Sinkhole** | Egress stage 0: DNS and HTTP answered locally so that outbound attempts appear to succeed while reaching nothing real |
| **Suspicion** | Estimated probability that the adversary believes they are inside a deception |

\pagebreak

# Appendix B. Proposal Cross-Reference

Every approved objective and research question, and where in this record it is satisfied.

| Approved item | Satisfied in | Note |
|---|---|---|
| O1 — Behavioural scoring engine | §6.1, §6.2 | Retained as a component; becomes evidence feeding intent inference |
| O2 — Three-tier escalation architecture | §6.3 | Identity retained; internally capabilities and states |
| O3 — Kubernetes orchestration | §6.3, §11.8 | Actuator plane; orchestration where it earns its place, at P6 |
| O4 — AI artifact generation | §6.6 | Inference and planning, plus offline artifact synthesis |
| O5 — Dynamic containment | §4 | Invariant plus instrumented egress gateway; stronger than the original |
| O6 — SIEM and intelligence pipeline | §5.4, §11.6 | Intelligence plane over the append-only log |
| O7 — Platform evaluation | §7 | Three-arm controlled experiment |
| RQ1 — Does adaptive escalation improve engagement and intelligence yield? | §7.1 | Arm B versus arm A |
| RQ2 — Do generated artifacts create sufficient realism? | §7.1, §6.2 | Arm C versus arm B; `suspicion` is the direct measure |
| RQ3 — Can elastic orchestration manage lifecycle at lab scale? | §6.4, §7.5 | Actuation latency and resource metrics against the stated budget |
| RQ4 — What is effectiveness across attacker profiles? | §7.5 | Per-profile breakdown across all three arms |

\pagebreak

# Appendix C. Approval Record

To be completed before phase P3 opens. Gate item 19 of §4.5 is not satisfied until section 2 below
carries a signature.

**1. Design record**

| | |
|---|---|
| Reviewed by | ................................................ |
| Role | Supervisor |
| Date | ................................................ |
| Signature | ................................................ |

**2. Authorisation to accept SSH authentication and to operate staged egress**

Confirming that the nineteen properties of §4.5 have been demonstrated, and authorising egress stage 0
with stage 1 subject to further approval.

| | |
|---|---|
| Gate verified by | ................................................ |
| Date verified | ................................................ |
| Authorised by | ................................................ |
| Role | Supervisor |
| Date | ................................................ |
| Signature | ................................................ |

**3. Authorisation for egress stage 1 (optional, phase P5)**

| | |
|---|---|
| Authorised by | ................................................ |
| Provider notified | ................................................ |
| Date | ................................................ |
| Signature | ................................................ |

\pagebreak

# Appendix D. Document Control

| | |
|---|---|
| Document | CyberSnare — Phase 0 Design Record |
| Version | 1.0 |
| Status | For review |
| Supersedes | Nothing. First issue |
| Related | *FYP Final Proposal — CyberSnare: Multi-Tier Adaptive Deception Platform* (FYP-1, approved) |
| Next artefact | Architecture document set, to be written only after this record is agreed |

**Change policy.** Sections 1, 2 and 4 are the substance of the claim and the safety case; changes to
them require the same review as the original. Section 8 is expected to shrink as decisions are
resolved, and each resolution should be recorded with its date and the person who made it. Section 9
is append-only: an element that returns from §9.2 must be added to §9.1 with the justification that
brought it back, so that the delta history remains complete.
