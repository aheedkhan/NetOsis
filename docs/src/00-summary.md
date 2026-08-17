# Executive Summary

CyberSnare was approved at FYP-1 as a *Multi-Tier Adaptive Deception Platform*: seven modules, three
escalating honeypot tiers, behavioural scoring, Kubernetes orchestration, AI-generated enterprise
artifacts, dynamic containment, and an ELK-based intelligence pipeline. That proposal established a
research identity worth pursuing. It did not, and was not required to, establish how the system should
be engineered.

This record is the result of taking the proposal apart and rebuilding it as something that can
actually be constructed, deployed on the public internet, and defended at a viva.

**The central change is one of identity.** CyberSnare is not a honeypot with tiers. It is an *adaptive
deception control plane* that orchestrates, selects, monitors and evolves deceptive environments based
on observed adversary behaviour and inferred intent. Honeypots become interchangeable actuators
underneath it. That inversion is what makes the contribution defensible, and it is what makes the
evaluation possible.

**The claim, stated narrowly enough to survive an examiner:**

> An intent-conditioned deception control plane that selects and adapts exposed deception capabilities
> according to inferred adversary objective, using behavioural scoring as evidence rather than as the
> sole escalation criterion.

Behavioural scoring — approved objective O1 — is retained in full. It becomes one source of evidence
feeding an intent model, rather than a scalar whose thresholds decide everything. The three-tier
concept remains part of the research identity, but internally deception is modelled as selectable
capabilities and states, so escalation no longer implies provisioning new infrastructure.

**Three mechanisms in the original design could not have worked as written**, and each is replaced
with a reason recorded. Escalation had no transport — nothing in the seven modules could move a
connection between tiers. Provisioning was slower than an attacker's reconnect: the proposal's own
literature cites eight commands in twenty-nine seconds, against pod creation and content generation
measured in tens of seconds. And containment was scheduled to activate at a threshold, leaving egress
open during exactly the window where it mattered. Containment is now a global invariant.

**Eleven further elements are explicitly not inherited** — arbitrary scoring weights, fixed
thresholds, seven controller states, Redis, per-IP attacker identity, ELK as the data path, a
composite effectiveness formula undefined under censoring, and Cowrie among them. Each is listed in
§9 with its replacement, so nothing disappears silently and every approved objective can be traced
forward.

**Milestone 1 is eight weeks and stands alone.** It delivers the sensor plane, custom SSH and HTTP
deception surfaces, successful authentication into a real but tightly restricted disposable shell, the
decision plane with three interchangeable policies, the telemetry model, and a three-arm controlled
experiment running on live internet traffic. Kubernetes, immersive environments, learned policy and
large-scale artifact generation are designed here and built later.

**The evaluation is the part most likely to be attacked, so it is designed first.** Three arms — static,
adaptive-without-AI, and intent-conditioned-with-AI — run concurrently against the same traffic
population, preceded by an A/A validation that tests whether the exposure points are comparable at
all. Engagement is analysed as time-to-event data with right-censoring, because most adversaries never
detect the deception and a session that never ends cannot be averaged. Hypotheses and analysis plan
are pre-registered before exposure begins.

**Safety is treated as an enabler rather than a restriction.** The attacker is granted internet access
because what their environment tries to contact is a second, independent stream of intent evidence
that host telemetry cannot fabricate. But the attacker never controls the path: all egress traverses
an instrumented gateway, beginning at a sinkhole stage that captures every intended destination while
reaching nothing real. Nineteen properties must be demonstrated — not asserted — before SSH
authentication is enabled at all.

Seven decisions remain open and are listed in §8, each with what it blocks and when it must be
resolved. The most consequential is the exposure configuration, which has not been purchased and is
therefore presented as a preference with two documented fallbacks rather than an assumption.
