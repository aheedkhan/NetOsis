#!/usr/bin/env bash
# Bootstrap cs-lab — Ubuntu 24.04, k3s, CyberSnare images + manifests.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
INSTALL_DIR="${CS_INSTALL_DIR:-/opt/cybersnare}"

echo "== CyberSnare lab bootstrap =="
echo "Install dir: $INSTALL_DIR"

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root: sudo $0" >&2
  exit 1
fi

apt-get update
apt-get install -y curl nftables wireguard

if ! command -v k3s >/dev/null 2>&1; then
  echo "Installing k3s..."
  curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="--write-kubeconfig-mode 644" sh -
fi

mkdir -p "$INSTALL_DIR"
if [ "$ROOT" != "$INSTALL_DIR" ]; then
  rsync -a --delete "$ROOT/" "$INSTALL_DIR/" \
    --exclude data --exclude .git --exclude dist
fi

cp "$INSTALL_DIR/deploy/org/firewall/nftables-lab.conf" /etc/nftables.conf
systemctl enable --now nftables

echo "Building container images..."
cd "$INSTALL_DIR"
if command -v podman >/dev/null 2>&1; then
  podman build -t localhost/cybersnare-python:lab -f containers/Dockerfile.python .
  podman build -t localhost/cybersnare-zeek:lab -f containers/Dockerfile.zeek .
  podman build -t localhost/cybersnare-gnn:lab -f containers/Dockerfile.gnn .
  podman save localhost/cybersnare-python:lab | k3s ctr images import -
  podman save localhost/cybersnare-zeek:lab | k3s ctr images import -
  podman save localhost/cybersnare-gnn:lab | k3s ctr images import -
else
  echo "podman not found — install podman or import images manually." >&2
  exit 1
fi

echo "Applying Kubernetes manifests..."
kubectl apply -k "$INSTALL_DIR/deploy/k8s/base"

echo
echo "Lab bootstrap complete."
echo "  kubectl -n cybersnare get pods"
echo "  Configure cs-edge WireGuard to 10.250.0.2 and DNAT deception ports."
