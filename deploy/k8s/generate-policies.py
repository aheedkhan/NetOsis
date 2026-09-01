#!/usr/bin/env python3
"""
Generate namespace and CiliumNetworkPolicy manifests from config/topology.json.

The compose deployment enforces zone segmentation with hand-written nftables
rulesets (deploy/org/firewall/*.nft). This is the same policy, expressed for
the Kubernetes deployment as Cilium's CRD — but both are meant to implement the
SAME zone graph, so this script reads it from topology.json rather than
re-declaring it a third time. If a zone or an edge changes, it changes in one
place and both deployment targets regenerate from it.

Every namespace gets a default-deny CiliumNetworkPolicy first (deny all
ingress/egress not explicitly allowed), then one policy per outgoing edge in
topology.json's `policy_edges`. An edge marked "containment" is deliberately
NOT translated into an allow rule — its only representation here is that it is
absent, which is what makes a containment violation actually impossible rather
than merely logged.

Usage:
    python3 deploy/k8s/generate-policies.py > deploy/k8s/generated/policies.yaml
"""

from __future__ import annotations

import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
TOPOLOGY = ROOT / "config" / "topology.json"

# topology.json zone id -> Kubernetes namespace. "transit" and "mgmt" are
# compose-only concepts (transit is the firewall-to-firewall link; mgmt is
# renamed cs-control here since the GNN and intelligence services live there
# too, which reads better as "control" than "mgmt" in a cluster context).
ZONE_NS = {
    "internet": "cs-internet",
    "dmz": "cs-dmz",
    "corp": "cs-corp",
    "datacenter": "cs-datacenter",
    "deception": "cs-deception",
    "egress": "cs-egress",
    "mgmt": "cs-control",
}

# Port sets referenced by topology.json's edge `detail` text — kept here
# rather than parsed out of prose, since the prose is for humans.
DMZ_TO_CORP_BLOCKED = [389, 636, 445, 139, 1433, 3306, 5432, 3389]
DECEPTION_TO_CORP_ALLOWED = [80, 139, 389, 445, 3389]
DNS_PORT = 53


def load_topology() -> dict:
    return json.loads(TOPOLOGY.read_text(encoding="utf-8"))


def namespace_yaml(ns: str, zone_id: str, trust: str) -> str:
    return f"""apiVersion: v1
kind: Namespace
metadata:
  name: {ns}
  labels:
    app.kubernetes.io/part-of: cybersnare
    cybersnare.io/zone: {zone_id}
    cybersnare.io/trust: {trust}
"""


def default_deny_yaml(ns: str) -> str:
    return f"""apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: default-deny
  namespace: {ns}
spec:
  endpointSelector: {{}}
  ingress: []
  egress:
    # DNS must survive every default-deny or nothing in the namespace can
    # resolve a Service name, cluster-internal or otherwise.
    - toEndpoints:
        - matchLabels:
            k8s:io.kubernetes.pod.namespace: kube-system
            k8s-app: kube-dns
      toPorts:
        - ports:
            - port: "53"
              protocol: UDP
            - port: "53"
              protocol: TCP
"""


def allow_all_egress_to_ns(name: str, ns: str, to_ns: str, ports: list[int] | None = None) -> str:
    port_block = ""
    if ports:
        port_lines = "\n".join(f'            - port: "{p}"\n              protocol: TCP' for p in ports)
        port_block = f"""
      toPorts:
        - ports:
{port_lines}"""
    return f"""apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: {name}
  namespace: {ns}
spec:
  endpointSelector: {{}}
  egress:
    - toEndpoints:
        - matchLabels:
            k8s:io.kubernetes.pod.namespace: {to_ns}{port_block}
"""


def deny_egress_ports_to_ns(name: str, ns: str, to_ns: str, denied_ports: list[int]) -> str:
    """
    'Restricted' edges (dmz->corp) are expressed as: allow the namespace, deny
    the specific ports that would matter if the DMZ were compromised. Cilium
    evaluates L4 allow/deny per rule; the simplest correct expression here is
    an allow rule that omits the denied ports from its toPorts allowlist while
    covering everything else the corp namespace actually serves (http on the
    decoy hosts). Kept narrow and explicit rather than "allow all except."
    """
    allowed_ports = [80]  # the decoy corp hosts serve http only
    port_lines = "\n".join(f'            - port: "{p}"\n              protocol: TCP' for p in allowed_ports)
    return f"""apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: {name}
  namespace: {ns}
  annotations:
    cybersnare.io/denied-ports: "{','.join(str(p) for p in denied_ports)}"
spec:
  endpointSelector: {{}}
  egress:
    - toEndpoints:
        - matchLabels:
            k8s:io.kubernetes.pod.namespace: {to_ns}
      toPorts:
        - ports:
{port_lines}
"""


def allow_ingress_from_ns(name: str, ns: str, from_ns: str, ports: list[int] | None = None) -> str:
    port_block = ""
    if ports:
        port_lines = "\n".join(f'            - port: "{p}"\n              protocol: TCP' for p in ports)
        port_block = f"""
      toPorts:
        - ports:
{port_lines}"""
    return f"""apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: {name}
  namespace: {ns}
spec:
  endpointSelector: {{}}
  ingress:
    - fromEndpoints:
        - matchLabels:
            k8s:io.kubernetes.pod.namespace: {from_ns}{port_block}
"""


def world_egress_yaml(ns: str) -> str:
    """internet -> outside the cluster entirely (attacker/operator pods dialling out to nothing real, but the rule has to exist for kubelet/DNS bootstrap traffic)."""
    return f"""apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: allow-world-egress
  namespace: {ns}
spec:
  endpointSelector: {{}}
  egress:
    - toEntities:
        - world
"""


def generate() -> str:
    topo = load_topology()
    zones = {z["id"]: z for z in topo["zones"]}
    edges = topo["policy_edges"]

    parts: list[str] = [
        "# GENERATED — do not hand-edit.\n"
        "# Source: config/topology.json, generator: deploy/k8s/generate-policies.py\n"
    ]

    for zone_id, ns in ZONE_NS.items():
        zone = zones.get(zone_id, {})
        parts.append(namespace_yaml(ns, zone_id, zone.get("trust", "unknown")))

    for ns in ZONE_NS.values():
        parts.append(default_deny_yaml(ns))

    # fw-agent (cs-control) shells out to kubectl to manage
    # CiliumClusterwideNetworkPolicy — the Kubernetes API server lives in the
    # `default` namespace's `kubernetes` Service, which none of the zone-to-
    # zone rules above cover, so without this kubectl hangs indefinitely
    # trying to reach it. `toEntities: [kube-apiserver]` is the entity Cilium
    # defines specifically for this rather than hardcoding the API server's
    # ClusterIP.
    parts.append(f"""apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: allow-control-to-apiserver
  namespace: {ZONE_NS['mgmt']}
spec:
  endpointSelector: {{}}
  egress:
    - toEntities:
        - kube-apiserver
""")

    # cs-deception and cs-control both need DNS resolved from kube-system,
    # already covered by default_deny_yaml's DNS carve-out above.

    for edge in edges:
        src_zone, dst_zone, verdict = edge["from"], edge["to"], edge["verdict"]
        if src_zone not in ZONE_NS or dst_zone not in ZONE_NS:
            continue  # transit — a compose-only firewall link, not a k8s namespace
        src_ns, dst_ns = ZONE_NS[src_zone], ZONE_NS[dst_zone]
        name = f"allow-{src_zone}-to-{dst_zone}"

        if verdict == "containment":
            # Deliberately no rule. Absence is the enforcement.
            continue
        if verdict == "deny":
            continue
        if verdict == "restricted" and src_zone == "dmz" and dst_zone == "corp":
            parts.append(deny_egress_ports_to_ns(name, src_ns, dst_ns, DMZ_TO_CORP_BLOCKED))
            # The egress side alone is not enough — Cilium enforces both ends
            # independently, so without a matching ingress rule in cs-corp the
            # connection is allowed out of cs-dmz and then silently dropped on
            # arrival. Same bug class as the missing zone->control direction
            # above, caught the same way: by actually testing the path rather
            # than reading the policy and assuming symmetry.
            parts.append(allow_ingress_from_ns(f"allow-ingress-{src_zone}-{dst_zone}", dst_ns, src_ns, [80]))
            continue
        if verdict == "restricted" and src_zone == "deception" and dst_zone == "corp":
            parts.append(allow_all_egress_to_ns(name, src_ns, dst_ns, DECEPTION_TO_CORP_ALLOWED))
            parts.append(allow_ingress_from_ns(f"allow-ingress-{src_zone}-{dst_zone}", dst_ns, src_ns, DECEPTION_TO_CORP_ALLOWED))
            continue
        if verdict == "allow" and dst_zone == "internet":
            parts.append(world_egress_yaml(src_ns))
            continue
        if verdict == "allow":
            parts.append(allow_all_egress_to_ns(name, src_ns, dst_ns))
            # The matching ingress side, so the destination namespace's
            # default-deny does not silently swallow a permitted flow.
            parts.append(allow_ingress_from_ns(f"allow-ingress-{src_zone}-{dst_zone}", dst_ns, src_ns))
            continue

    # Intra-namespace traffic (control plane services calling each other
    # inside cs-control, deception surfaces reaching the sensor pod they share
    # a namespace with) needs an explicit same-namespace allow, since Cilium's
    # default-deny with an empty ingress/egress list blocks same-namespace
    # traffic too unless a rule says otherwise.
    for zone_id, ns in ZONE_NS.items():
        parts.append(allow_all_egress_to_ns(f"allow-intra-{zone_id}", ns, ns))
        parts.append(allow_ingress_from_ns(f"allow-intra-ingress-{zone_id}", ns, ns))

    # cs-internet needs to reach the published deception and DMZ services —
    # already covered by internet->dmz and internet->deception allow rules
    # above. cs-control needs to reach every namespace to ingest events and
    # push manifests/blocklists; that is deliberately broad since it is the
    # control plane, mirroring compose's mgmt network having a leg everywhere.
    for zone_id, ns in ZONE_NS.items():
        if zone_id == "mgmt":
            continue
        # control -> zone (fw-agent pushing blocklists, decision reading
        # manifests from wherever, etc.)
        parts.append(allow_all_egress_to_ns(f"allow-control-to-{zone_id}", "cs-control", ns))
        parts.append(allow_ingress_from_ns(f"allow-ingress-control-{zone_id}", ns, "cs-control"))
        # zone -> control — the direction that actually carries almost all of
        # this traffic: every surface is a CLIENT of logger/decision/gnn,
        # reporting events and polling manifests, not a server control calls
        # into. Missing this half meant every zone's egress was allowed by
        # its own namespace policy but arrived at a cs-control ingress that
        # never admitted it — DNS resolved, the connection just hung until
        # timeout, which is what actually happened before this was added.
        parts.append(allow_all_egress_to_ns(f"allow-{zone_id}-to-control", ns, "cs-control"))
        parts.append(allow_ingress_from_ns(f"allow-ingress-{zone_id}-control", "cs-control", ns))

    return "---\n".join(parts)


if __name__ == "__main__":
    sys.stdout.write(generate())
