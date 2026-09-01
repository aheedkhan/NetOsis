#!/usr/bin/env bash
# One-time host prep for rootless Podman on Fedora. Installs nothing except what you choose via dnf.
set -euo pipefail

if ! command -v podman >/dev/null 2>&1; then
  cat >&2 <<'EOF'
Podman is not installed. On Fedora:

  sudo dnf install -y podman

That is the only required host package for CyberSnare.
EOF
  exit 1
fi

if command -v systemctl >/dev/null 2>&1; then
  systemctl --user enable --now podman.socket 2>/dev/null || \
    systemctl --user start podman.socket 2>/dev/null || true
fi

if ! podman compose version >/dev/null 2>&1; then
  cat >&2 <<'EOF'
podman compose is unavailable. On Fedora 40+ it ships with podman.
If missing:

  sudo dnf install -y podman-compose
EOF
  exit 1
fi

echo "Podman $(podman --version | awk '{print $3}') is ready."
echo "Start the lab:  ./cs up   (or: make up)"
