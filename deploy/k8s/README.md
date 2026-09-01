# k3s org deployment on cs-lab

Apply the full CyberSnare stack to a single-node (or multi-node) k3s cluster on Ubuntu 24.04.

## Prerequisites

- Ubuntu 24.04 on **cs-lab**
- Repo at `/opt/cybersnare` (config bind-mount in decision deployment)
- Images built locally and imported into k3s:

```bash
cd /opt/cybersnare
podman build -t localhost/cybersnare-python:lab -f containers/Dockerfile.python .
podman build -t localhost/cybersnare-zeek:lab -f containers/Dockerfile.zeek .
podman build -t localhost/cybersnare-gnn:lab -f containers/Dockerfile.gnn .

# k3s uses containerd — import from podman
podman save localhost/cybersnare-python:lab | sudo k3s ctr images import -
podman save localhost/cybersnare-zeek:lab | sudo k3s ctr images import -
podman save localhost/cybersnare-gnn:lab | sudo k3s ctr images import -
```

## Deploy

```bash
sudo kubectl apply -k deploy/k8s/base
kubectl -n cybersnare get pods -w
```

## Policy arms

Edit `deploy/k8s/base/configmap.yaml`:

| Arm | CS_POLICY | CS_GNN_ENABLED |
|-----|-----------|----------------|
| A (static) | P0 | 0 |
| B (adaptive score) | P1 | 1 |
| C (intent + GNN) | P2 | 1 |

## NodePorts (lab host)

| NodePort | Service |
|----------|---------|
| 30222 | SSH deception |
| 30808 | HTTP deception |
| 30443 | HTTPS deception |

Wire **cs-edge** nftables DNAT to these ports over WireGuard (`10.250.0.2`).

## Real vs fake in cluster

- **Real**: `gitlab-mirror` (nginx static — internal realism)
- **Fake**: deception-sensor pod, sinkhole, sandbox

Add more real services under `workloads.yaml` with label `cybersnare.io/service-type: real`.
