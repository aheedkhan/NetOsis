# CyberSnare org deployment — two Ubuntu servers

Production-shaped layout: one **edge/DMZ** host with a real corporate web presence and firewall, one **lab** host running k3s with real internal services plus fake deception surfaces orchestrated by the control plane.

## Server roles

| Host | Role | OS | What runs |
|------|------|-----|-----------|
| **cs-edge** | DMZ / exposure | Ubuntu 24.04 LTS | nftables FW, nginx (real site), WireGuard client, DNAT to lab |
| **cs-lab** | Deception + control | Ubuntu 24.04 LTS | k3s, CyberSnare stack, Zeek sensor pod, GNN scorer, sinkhole |

```
                    Internet
                        │
                        ▼
              ┌─────────────────────┐
              │      cs-edge        │
              │  nftables (FW)      │
              │  nginx :443 REAL    │  ← NexusCorp public marketing site
              │  WG 10.250.0.1      │
              └──────────┬──────────┘
                         │ WireGuard tunnel (outbound dial, no inbound FW rule)
                         ▼
              ┌─────────────────────┐
              │      cs-lab         │
              │  k3s cluster        │
              │  WG 10.250.0.2      │
              ├─────────────────────┤
              │ REAL (internal)     │  gitlab-mirror, ldap-mock, dns-internal
              │ FAKE (deception)    │  ssh/http L1–L3, sinkhole, sandbox
              │ CONTROL             │  logger, decision, gnn-scorer, zeek
              └─────────────────────┘
```

## VLAN / address plan (lab host)

| Network | CIDR | Purpose |
|---------|------|---------|
| mgmt | `10.200.1.0/24` | logger, decision, gnn-scorer, zeek-ingest |
| deception | `10.200.2.0/24` | sensor pod (ssh + http + zeek share netns) |
| egress | `10.200.3.0/24` | sinkhole, sandbox |
| wireguard | `10.250.0.0/24` | edge ↔ lab tunnel |

## Real vs fake services

| Service | Real or fake | Where | Notes |
|---------|--------------|-------|-------|
| Public HTTPS marketing site | **Real** | cs-edge nginx | Legitimate org front door |
| Internal GitLab mirror | **Real** | cs-lab k8s | Low-value real app for realism |
| LDAP mock (read-only) | **Real** | cs-lab k8s | Directory-shaped traffic, no secrets |
| SSH :2222 | **Fake** | deception pod | asyncssh KEX, auth per manifest |
| Employee portal :8080/:8443 | **Fake** | deception pod | NexusCorp deception surface |
| DNS/HTTP egress | **Fake** | sinkhole | stage-0 sinkhole, never reaches internet |
| Sandbox shell | **Fake** | sandbox pod | restricted when L2+ enabled |

## Deception levels (all tiers)

| Level | Policy arm | Capabilities exposed |
|-------|------------|----------------------|
| **L0** Observe | A/B/C | Sensor only, minimal response |
| **L1** Attract | A (P0 static) | SSH/HTTP exposed, auth closed |
| **L2** Engage | B (P1 score) / C (P2 intent) | Auth open, restricted shell, populated FS |
| **L3** Immerse | C (P2 + GNN) | Internal network hop, cred material, richer FS |
| **BURN** | any | Freeze capabilities, harvest, disengage |
| **BLOCK** | any | Safety circuit-breaker |

## GNN dynamic scoring

The **gnn-scorer** pod builds an actor graph from recent events (nodes = actors/IPs/fingerprints, edges = linkage + session adjacency) and returns:

- `intel_gain` — expected intelligence yield
- `suspicion` — P(adversary knows it's deception)
- `novelty` — new information still available
- `intent` — distribution over objective taxonomy

**P1** uses GNN scores in the utility function. **P2** selects manifests from intent distribution. Decision budget stays **< 100 ms** on the fast path; GNN runs async with cached scores refreshed every few seconds.

## Bootstrap order

1. **cs-lab**: `./deploy/scripts/bootstrap-lab.sh` — k3s, namespaces, apply manifests
2. **cs-edge**: `./deploy/scripts/bootstrap-edge.sh` — nftables, nginx, WireGuard to lab
3. Verify: `./cs verify-org` (from repo root on either host with kubectl access)

See `deploy/k8s/README.md` for manifest details.
