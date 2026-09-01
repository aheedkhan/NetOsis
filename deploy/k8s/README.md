# CyberSnare on kind — a real cluster, not manifests that only look like one

This is a second, independent deployment target for the same design as the
compose lab (`compose.yml`) — the same zones, the same policy graph
(`config/topology.json`), the same service code, running on a real local
Kubernetes cluster instead of Podman bridges. Nothing here is simulated:
Cilium enforces every `CiliumNetworkPolicy` at the eBPF level in the kernel,
so a "blocked" flow is actually dropped, not merely declared blocked in YAML.

## Why Cilium instead of the default CNI

`kind`'s default CNI (kindnet) wires pod routing but does not enforce
`NetworkPolicy` at all — every pod could reach every other pod regardless of
what a policy said. Segmentation is this project's whole argument, so that is
disqualifying. Cilium was chosen over the more common alternative (Calico)
for one additional reason: **Hubble**, Cilium's flow observability layer,
gives real per-packet accept/deny visibility with essentially no extra code —
the same kind of evidence `services/fw_agent` hand-rolls from nftables set
counters for the compose deployment, here produced by production-grade
tooling instead. (Hubble→canonical-event wiring is not built yet — see
**Status** below.)

## Why namespaces instead of multi-homed firewall containers

The compose deployment's firewalls (`cs-edge-fw`, `cs-core-fw`) are containers
attached to five different bridge networks at once, each with its own nftables
ruleset doing real DNAT and segmentation. Kubernetes pods do not work that
way — a pod has one network identity on one flat pod network by design, and
forcing a multi-homed pod through Multus would fight the platform rather than
use it. So here, each zone in `config/topology.json` is a **Namespace**, and
segmentation is a **default-deny `CiliumNetworkPolicy` per namespace plus one
explicit allow policy per edge** in the topology graph — the idiomatic
Kubernetes expression of the same policy, not a lesser one. Absence of a rule
is what makes an edge marked `containment` in `topology.json` (e.g.
deception → datacenter) actually impossible, exactly as the nftables
ruleset's missing forward rule does for the compose deployment.

## Everything is generated from config/topology.json

| Generator | Reads | Produces |
|---|---|---|
| `deploy/k8s/generate-policies.py` | `topology.json` zones + `policy_edges` | Namespaces + `CiliumNetworkPolicy` (default-deny per namespace, one allow per edge) |
| `deploy/k8s/generate-org-hosts.py` | `topology.json` hosts + `deploy/org/sites/` + `deploy/org/tls/` | ConfigMap/Secret/Deployment/Service per DMZ/corp/datacenter host |
| `deploy/k8s/generate-config.py` | `config/*.json` | The `cs-manifests` and `cs-shell-users` ConfigMaps the control plane and deception surface mount |

Run them (or `deploy/k8s/deploy.sh`, which does) after changing the topology
or any manifest-*.json capability ladder — the generated output under
`deploy/k8s/generated/` is derived and not meant to be hand-edited.

## What differs from the compose deployment

- **Addressing.** No VIP/DNAT layer — an outside pod reaches the deception
  surface at `sensor.cs-deception.svc.cluster.local` directly. Whether it is
  *allowed* to is entirely a NetworkPolicy decision, which is arguably a
  cleaner test of segmentation than obscuring the address would be.
- **Blocking.** The compose deployment's decision plane blocks an address by
  adding it to an nftables set inside a firewall container. There is no
  equivalent object here, so `services/k8s_fw_agent` (deployed as `fw-agent`
  in `cs-control`) exposes the identical `/v1/block` / `/v1/unblock` /
  `/v1/blocked` API but maintains one `CiliumClusterwideNetworkPolicy` with an
  `ingressDeny` rule instead — evaluated by Cilium before any allow policy,
  the same precedence relationship the nftables `blocked` set has over its
  own accept rules. `lib/cs/policies.py` and `services/decision` are
  unmodified; only `CS_FIREWALLS` in `deploy/k8s/base/control-plane.yaml`
  points them at a different backend.
- **The Zeek capture filter.** The compose sensor excludes traffic to a fixed
  management CIDR to avoid capturing its own control-plane calls as adversary
  telemetry. That CIDR doesn't exist here — control-plane traffic travels over
  the cluster's Service network instead — so `deploy/k8s/base/deception.yaml`
  overrides the filter to exclude by **port** (8088/9000/9100, the ports our
  own containers dial as clients) instead of by address. Same bug class,
  CNI-independent fix.
- **Pod-level resource limits.** Compose's `pids_limit: 64` on the sandbox has
  no direct Pod-spec equivalent; `resources.limits` (cpu/memory/ephemeral-
  storage) is what's set here. A process-count ceiling would need a
  `LimitRange` or seccomp policy layered on top — not done.

## Prerequisites

Installed to `~/.local/bin` by this session; a fresh machine needs:

```bash
# kind, kubectl, cilium CLI — pin whatever the current stable release is
curl -fsSL -o kind https://kind.sigs.k8s.io/dl/latest/kind-linux-amd64
curl -fsSL -o kubectl "https://dl.k8s.io/release/$(curl -Ls https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
curl -fsSL -o cilium.tar.gz "https://github.com/cilium/cilium-cli/releases/latest/download/cilium-linux-amd64.tar.gz"
```

Needs a **real Docker daemon** (kind's primary supported provider) — this
machine already had one (`docker --version`) independent of the Podman setup
the compose deployment uses; the two coexist without conflict.

## Deploy

```bash
./cs k8s-cluster-up          # kind create cluster, default CNI disabled
./cs k8s-cilium-install      # Cilium + Hubble relay
./cs k8s-status              # wait for it — image pulls are the slow part
./cs k8s-up                  # regenerate manifests, load images, apply everything
./deploy/k8s/verify.sh       # real connection attempts proving segmentation
```

`./cs k8s-attacker` / `./cs k8s-operator` run the same automated / hand-paced
demo scripts as the compose deployment's `./cs attacker` / `./cs operator`,
against the pods in `cs-internet`.

## Status

Built and verified this session: cluster, Cilium/Hubble, all namespaces and
NetworkPolicy, every zone's workloads, the k8s-native blocking mechanism.
**Not yet done:** a Hubble→canonical-event adapter (so denied/allowed flows
join the same JSONL log the compose deployment's `fw_agent` writes to) — until
that exists, `cs-control`'s `logger` only sees events the application
services themselves emit (ssh/http/sinkhole/decision), not raw perimeter
accept/deny telemetry. Segmentation itself is fully enforced regardless;
what's missing is turning Cilium's own visibility into this project's event
schema.
