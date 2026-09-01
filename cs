#!/usr/bin/env bash
# CyberSnare lab controller — host needs only podman and bash.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

COMPOSE="podman compose"
PYTHON_IMG=localhost/cybersnare-python:lab

podman_ready() {
  command -v podman >/dev/null 2>&1 || {
    echo "podman is required. Run: sudo dnf install -y podman" >&2
    exit 1
  }
  if command -v systemctl >/dev/null 2>&1; then
    systemctl --user start podman.socket 2>/dev/null || true
  fi
}

ensure_data_dirs() {
  mkdir -p data/events data/manifests data/zeek
}

usage() {
  cat <<'EOF'
CyberSnare local lab — Podman only on the host.

Usage: ./cs <command>

  bootstrap   Check podman / compose and enable user socket
  up          Build images and start all containers
  up-adaptive Start with P1 policy + GNN scorer enabled (Arm B)
  up-p2         Start with P2 intent-conditioned policy (Arm C)
  set-level L2  Pin manifest level for lab testing
  reset-lab      Unpin and reset to L1 (after automated BURN)
  down          Stop and remove containers/networks
  rebuild       Force-recreate the stack
  ps            Container status
  logs          Tail compose logs
  health        Probe logger + decision /health (no host curl)
  events        Show last 20 JSONL events (no host python)
  verify        Full integration test
  gate          §4.5 authentication gate (19 properties)
  verify-l2     L2 engage smoke test (after gate + set-level L2)
  monitor       Live actor + transition activity dashboard
  milestone     Milestone 1 full verification (lab + P4/P5)
  redteam       Scripted evaluation profiles
  analyze       Generate milestone1-report.json from JSONL
  aa-validate   A/A exposure parity check
  collect       Daily collection snapshot for three-arm study
  dashboard-build  Build React dashboard (Framer Motion UI)
  arch-pdf        Build architecture PDF (docs/CyberSnare-Architecture-Lab.pdf)
  attack-map-pdf  Build Attack Map guide PDF (served on dashboard)
  attacker      Start the attacker (outside, blocked by classifier)
  attacker-shell  SSH helper into the attacker (port 2220, user kali)
  operator      Start the human-paced operator (outside, gets engaged)
  operator-shell  SSH helper into the operator container (port 2221)
  observe       Bring the lab up with the operator gate OFF (for corpus collection)
  train-gnn     Train the actor graph model on data/events/events.jsonl
  blocked       Show addresses currently dropped at each firewall
  export      Save built images to dist/ (offline transfer)
  import      Load images from dist/
  help        This message

Examples:
  ./cs bootstrap && ./cs up && ./cs verify
EOF
}

cmd="${1:-help}"
shift || true

case "$cmd" in
  bootstrap)
    exec "$ROOT/scripts/bootstrap.sh"
    ;;
  up)
    podman_ready
    ensure_data_dirs
    exec $COMPOSE up -d --build "$@"
    ;;
  up-adaptive)
    podman_ready
    ensure_data_dirs
    exec $COMPOSE -f compose.yml -f compose.adaptive.yml up -d --build "$@"
    ;;
  up-p2)
    podman_ready
    ensure_data_dirs
    exec $COMPOSE -f compose.yml -f compose.p2.yml up -d --build "$@"
    ;;
  down)
    podman_ready
    exec $COMPOSE down --remove-orphans "$@"
    ;;
  rebuild)
    podman_ready
    ensure_data_dirs
    exec $COMPOSE up -d --build --force-recreate "$@"
    ;;
  ps)
    podman_ready
    exec $COMPOSE ps "$@"
    ;;
  logs)
    podman_ready
    exec $COMPOSE logs --tail=80 "$@"
    ;;
  health)
    podman_ready
    podman run --rm --network host "$PYTHON_IMG" \
      python -c "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:18088/health', timeout=3).read().decode())"
    podman run --rm --network host "$PYTHON_IMG" \
      python -c "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:19000/health', timeout=3).read().decode())"
    ;;
  events)
    podman_ready
    podman run --rm --network host "$PYTHON_IMG" \
      python -c "import json,urllib.request; print(json.dumps(json.loads(urllib.request.urlopen('http://127.0.0.1:18088/v1/tail?n=20',timeout=5).read()), indent=2))"
    ;;
  verify)
    podman_ready
    exec "$ROOT/scripts/verify.sh"
    ;;
  gate)
    podman_ready
    exec "$ROOT/scripts/gate-auth.sh"
    ;;
  verify-l2)
    podman_ready
    exec "$ROOT/scripts/verify-l2.sh"
    ;;
  monitor)
    podman_ready
    PYTHONPATH="$ROOT/lib:$ROOT" exec python3 "$ROOT/scripts/monitor.py" "$@"
    ;;
  milestone)
    podman_ready
    exec "$ROOT/scripts/milestone-verify.sh"
    ;;
  redteam)
    podman_ready
    exec "$ROOT/scripts/redteam-profiles.sh" "$@"
    ;;
  analyze)
    PYTHONPATH="$ROOT/lib:$ROOT" exec python3 "$ROOT/scripts/analyze-milestone.py" "$@"
    ;;
  aa-validate)
    exec "$ROOT/scripts/aa-validate.sh"
    ;;
  collect)
    exec "$ROOT/scripts/collect-snapshot.sh"
    ;;
  dashboard-build)
    exec "$ROOT/scripts/build-dashboard.sh"
    ;;
  arch-pdf)
    exec "$ROOT/scripts/build-architecture-pdf.sh"
    ;;
  attack-map-pdf)
    exec "$ROOT/scripts/build-attack-map-pdf.sh"
    ;;
  export)
    podman_ready
    mkdir -p dist
    for img in localhost/cybersnare-python:lab localhost/cybersnare-zeek:lab localhost/cybersnare-firewall:lab; do
      if ! podman image exists "$img" 2>/dev/null; then
        echo "Missing $img — run './cs up' first." >&2
        exit 1
      fi
    done
    podman save -o dist/cybersnare-python.tar localhost/cybersnare-python:lab
    podman save -o dist/cybersnare-zeek.tar localhost/cybersnare-zeek:lab
    podman save -o dist/cybersnare-firewall.tar localhost/cybersnare-firewall:lab
    if ! podman image exists localhost/cybersnare-verify:lab 2>/dev/null; then
      podman build -t localhost/cybersnare-verify:lab -f containers/Dockerfile.verify .
    fi
    podman save -o dist/cybersnare-verify.tar localhost/cybersnare-verify:lab
    if podman image exists localhost/cybersnare-gnn:lab 2>/dev/null; then
      podman save -o dist/cybersnare-gnn.tar localhost/cybersnare-gnn:lab
    fi
    if podman image exists localhost/cybersnare-attacker:lab 2>/dev/null; then
      podman save -o dist/cybersnare-attacker.tar localhost/cybersnare-attacker:lab
    fi
    echo "Images written to dist/*.tar — copy the repo + dist/ to another Fedora host."
    ;;
  import)
    podman_ready
    for tar in dist/cybersnare-python.tar dist/cybersnare-zeek.tar dist/cybersnare-firewall.tar \
               dist/cybersnare-verify.tar dist/cybersnare-gnn.tar dist/cybersnare-attacker.tar; do
      if [ -f "$tar" ]; then
        podman load -i "$tar"
      else
        echo "Skip missing $tar"
      fi
    done
    echo "Import done. Run: ./cs up"
    ;;
  k8s-apply)
    podman_ready
    kubectl apply -k deploy/k8s/base
    ;;
  k8s-status)
    kubectl -n cybersnare get pods
    ;;
  set-level)
    exec "$ROOT/scripts/set-level.sh" "${1:-L2}"
    ;;
  reset-lab)
    rm -f "$ROOT/data/manifests/.pinned"
    exec "$ROOT/scripts/set-level.sh" L1
    ;;
  attacker)
    podman_ready
    exec "$ROOT/scripts/attacker-up.sh"
    ;;
  attacker-shell)
    podman_ready
    echo "password: kali"
    exec ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 2220 kali@127.0.0.1
    ;;
  operator)
    podman_ready
    exec "$ROOT/scripts/operator-up.sh"
    ;;
  operator-shell)
    podman_ready
    echo "password: kali"
    exec ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 2221 kali@127.0.0.1
    ;;
  observe)
    podman_ready
    ensure_data_dirs
    exec $COMPOSE -f compose.yml -f compose.adaptive.yml -f compose.observe.yml up -d --build "$@"
    ;;
  train-gnn)
    podman_ready
    podman run --rm \
      -v "$ROOT/lib:/app/lib:ro,z" \
      -v "$ROOT/scripts:/app/scripts:ro,z" \
      -v "$ROOT/data:/app/data:z" \
      -w /app -e PYTHONPATH=/app/lib:/app \
      localhost/cybersnare-gnn:lab \
      python3 scripts/train-gnn.py --events data/events/events.jsonl --out data/models/actor-gnn.pt "$@"
    echo "Restart the scorer to load it: podman restart cs-gnn"
    ;;
  blocked)
    podman_ready
    for fw in cs-edge-fw:edge cs-core-fw:core; do
      name="${fw%%:*}"; role="${fw##*:}"
      echo "== $role ($name) =="
      podman exec "$name" python3 -c "import urllib.request;print(urllib.request.urlopen('http://127.0.0.1:9400/v1/blocked',timeout=3).read().decode())" 2>/dev/null || echo "  unreachable"
    done
    ;;
  bootstrap-lab)
    exec sudo "$ROOT/deploy/scripts/bootstrap-lab.sh"
    ;;
  bootstrap-edge)
    exec sudo "$ROOT/deploy/scripts/bootstrap-edge.sh"
    ;;
  help|-h|--help)
    usage
    ;;
  *)
    echo "Unknown command: $cmd" >&2
    usage >&2
    exit 1
    ;;
esac
