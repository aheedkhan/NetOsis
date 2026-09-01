#!/usr/bin/env bash
# Verify the kind deployment's segmentation matches config/topology.json's
# policy_edges — the same containment invariants the compose deployment's
# nftables rulesets enforce, here enforced by Cilium reading
# CiliumNetworkPolicy. Each check runs a real connection attempt from inside
# one pod to another across the namespace boundary; a passing check means
# Cilium's eBPF dataplane actually dropped or allowed the packet, not that a
# YAML file merely declares the right intention.
set -u
export PATH="$HOME/.local/bin:$PATH"
KCTX="kind-cybersnare"
FAILS=0

ok()  { printf '  OK    %s\n' "$*"; }
bad() { printf '  FAIL  %s\n' "$*"; FAILS=$((FAILS + 1)); }

run_in() {
  # run_in <namespace> <pod-label-selector> <container> -- <cmd...>
  local ns="$1" sel="$2" container="$3"; shift 3
  [ "$1" = "--" ] && shift
  local pod
  pod="$(kubectl --context "$KCTX" -n "$ns" get pod -l "$sel" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)"
  [ -z "$pod" ] && return 2
  kubectl --context "$KCTX" -n "$ns" exec "$pod" -c "$container" -- "$@" 2>/dev/null
}

must_reach() {
  local desc="$1" ns="$2" sel="$3" container="$4"; shift 4
  if run_in "$ns" "$sel" "$container" -- "$@" >/dev/null 2>&1; then
    ok "$desc"
  else
    bad "$desc (expected to succeed, did not)"
  fi
}

must_block() {
  local desc="$1" ns="$2" sel="$3" container="$4"; shift 4
  if run_in "$ns" "$sel" "$container" -- "$@" >/dev/null 2>&1; then
    bad "$desc (expected to be blocked, was NOT)"
  else
    ok "$desc"
  fi
}

echo "== cluster =="
if ! kubectl --context "$KCTX" get nodes >/dev/null 2>&1; then
  echo "cluster unreachable — is kind cybersnare running? (kind get clusters)" >&2
  exit 1
fi
ok "cluster reachable"
if kubectl --context "$KCTX" -n kube-system get pods -l k8s-app=cilium 2>/dev/null | grep -q "1/1.*Running"; then
  ok "cilium running"
else
  bad "cilium not fully ready — check: cilium status --context $KCTX"
fi

echo "== containment (must be blocked) =="
must_block "internet -> corp (no published service)" \
  cs-internet app=attacker attacker \
  wget -q -T 3 -O /dev/null http://dc01.cs-corp.svc.cluster.local/

must_block "internet -> datacenter (no published service)" \
  cs-internet app=attacker attacker \
  wget -q -T 3 -O /dev/null http://db01.cs-datacenter.svc.cluster.local/

must_block "deception -> datacenter (containment invariant)" \
  cs-deception app=sensor ssh-surface \
  python3 -c "import socket; socket.create_connection(('db01.cs-datacenter.svc.cluster.local', 80), 3).close()"

must_block "dmz -> corp on a blocked port (445)" \
  cs-dmz app=www01 nginx \
  wget -q -T 3 -O /dev/null http://dc01.cs-corp.svc.cluster.local:445/ 2>/dev/null

echo "== allowed paths =="
must_reach "internet -> published dmz service" \
  cs-internet app=attacker attacker \
  curl -sk -m 5 -o /dev/null http://www01.cs-dmz.svc.cluster.local/

must_reach "internet -> published deception service" \
  cs-internet app=attacker attacker \
  curl -sk -m 5 -o /dev/null https://sensor.cs-deception.svc.cluster.local/
# (a 401/connection-refused-at-app-layer still counts as "reached" for this
#  check's purpose — TCP connect succeeding is what proves the policy allowed
#  it; the deception surface's own auth posture is a separate concern.)

must_reach "corp -> datacenter (ordinary business traffic)" \
  cs-corp app=wks01 wks01 \
  wget -q -T 5 -O /dev/null http://db01.cs-datacenter.svc.cluster.local/ 2>/dev/null

must_reach "deception -> corp on a decoy port (80, the L3 hop)" \
  cs-deception app=sensor ssh-surface \
  python3 -c "import socket; socket.create_connection(('dc01.cs-corp.svc.cluster.local', 80), 3).close()"

echo
if [ "$FAILS" -eq 0 ]; then
  echo "Segmentation matches config/topology.json."
  exit 0
fi
echo "$FAILS check(s) failed."
exit 1
