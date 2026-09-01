#!/usr/bin/env bash
# Kill-switch drill for property 17 — stop and restart sandbox quickly.
set -euo pipefail
podman kill cs-sandbox 2>/dev/null || true
sleep 0.2
podman start cs-sandbox 2>/dev/null || podman restart cs-sandbox
