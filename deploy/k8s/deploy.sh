#!/usr/bin/env bash
# Deploy CyberSnare to the local kind cluster.
#
# Order matters: namespaces + NetworkPolicy first (so nothing is briefly
# unprotected while workloads come up), then config, then the control plane
# (everything else's dependency), then the zone workloads, then the demo
# actors last.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
export PATH="$HOME/.local/bin:$PATH"
KCTX="kind-cybersnare"

log() { echo "== $* =="; }

log "regenerating manifests from config/topology.json"
python3 deploy/k8s/generate-policies.py > deploy/k8s/generated/policies.yaml
python3 deploy/k8s/generate-org-hosts.py > deploy/k8s/generated/org-hosts.yaml
python3 deploy/k8s/generate-config.py > deploy/k8s/generated/config.yaml

log "loading images into the kind nodes"
for img in cybersnare-python cybersnare-zeek cybersnare-gnn cybersnare-attacker cybersnare-fw-agent-k8s; do
  if podman image exists "localhost/${img}:lab" 2>/dev/null; then
    podman save "localhost/${img}:lab" -o "/tmp/${img}.tar"
    kind load image-archive "/tmp/${img}.tar" --name cybersnare
    rm -f "/tmp/${img}.tar"
  else
    echo "  SKIP ${img} — not built (podman build -t localhost/${img}:lab ...)"
  fi
done

log "namespaces + NetworkPolicy"
kubectl --context "$KCTX" apply -f deploy/k8s/generated/policies.yaml

log "waiting for cilium (namespace enforcement depends on it)"
cilium status --context "$KCTX" --wait --wait-duration 3m || true

log "config (manifests, shell-users)"
kubectl --context "$KCTX" apply -f deploy/k8s/generated/config.yaml

log "control plane"
kubectl --context "$KCTX" apply -f deploy/k8s/base/fw-agent.yaml
kubectl --context "$KCTX" apply -f deploy/k8s/base/control-plane.yaml

log "org hosts (dmz, corp, datacenter)"
kubectl --context "$KCTX" apply -f deploy/k8s/generated/org-hosts.yaml

log "deception + egress"
kubectl --context "$KCTX" apply -f deploy/k8s/base/deception.yaml
kubectl --context "$KCTX" apply -f deploy/k8s/base/egress.yaml

log "demo actors (attacker, operator)"
kubectl --context "$KCTX" apply -f deploy/k8s/base/internet.yaml

log "done — watch rollout with: kubectl --context $KCTX get pods -A -w"
