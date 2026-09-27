#!/usr/bin/env bash
# Deploy NetOsis tree to a lab host over SSH (optionally via ProxyJump).
# Does NOT modify Proxmox bridges or OPNsense — see ops/proxmox/ for proposed steps.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ -f "$ROOT/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$ROOT/.env"
  set +a
fi

LAB_SSH_HOST="${LAB_SSH_HOST:-}"
LAB_SSH_USER="${LAB_SSH_USER:-root}"
LAB_SSH_PORT="${LAB_SSH_PORT:-22}"
LAB_REMOTE_DIR="${LAB_REMOTE_DIR:-/opt/netosis}"
LAB_SSH_JUMP="${LAB_SSH_JUMP:-}"   # optional user@host for ProxyJump
DRY_RUN="${DRY_RUN:-0}"

usage() {
  cat <<EOF
Usage: $(basename "$0") [--dry-run]

Requires in .env (or environment):
  LAB_SSH_HOST=192.168.30.50          # honeypot VM / lab host
  LAB_SSH_USER=root
  LAB_SSH_PORT=22
  LAB_REMOTE_DIR=/opt/netosis
  LAB_SSH_JUMP=user@172.30.227.1      # optional ProxyJump (if SSH on jump box)

Notes:
  JUMPBOX_RDP_TARGET is FreeRDP-only. For code push you need SSH on LAB_SSH_HOST
  (and optionally LAB_SSH_JUMP). Bring VPN up first: scripts/lab-access/start-vpn-rdp.sh
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi
if [[ "${1:-}" == "--dry-run" ]]; then
  DRY_RUN=1
fi

if [[ -z "$LAB_SSH_HOST" ]]; then
  echo "[!] Set LAB_SSH_HOST in .env (target honeypot / lab Linux host)." >&2
  usage
  exit 1
fi

SSH_OPTS=(-p "$LAB_SSH_PORT" -o StrictHostKeyChecking=accept-new)
if [[ -n "$LAB_SSH_JUMP" ]]; then
  SSH_OPTS+=(-J "$LAB_SSH_JUMP")
fi

RSYNC_SSH="ssh ${SSH_OPTS[*]}"
DEST="${LAB_SSH_USER}@${LAB_SSH_HOST}:${LAB_REMOTE_DIR}/"

echo "[*] Dest: $DEST"
echo "[*] Jump: ${LAB_SSH_JUMP:-"(none)"}"

EXCLUDES=(
  --exclude '.git/'
  --exclude '.venv/'
  --exclude '__pycache__/'
  --exclude '.pytest_cache/'
  --exclude 'data/'
  --exclude '.env'
  --exclude '*.ovpn'
  --exclude 'openvpn-auth.txt'
  --exclude 'Text File.txt'
)

if [[ "$DRY_RUN" == "1" ]]; then
  EXCLUDES+=(--dry-run)
  echo "[*] Dry run"
fi

# Ensure remote dir exists
ssh "${SSH_OPTS[@]}" "${LAB_SSH_USER}@${LAB_SSH_HOST}" "mkdir -p '$LAB_REMOTE_DIR'"

rsync -az --delete "${EXCLUDES[@]}" \
  -e "$RSYNC_SSH" \
  "$ROOT/" "$DEST"

echo "[*] Sync complete (secrets .env not copied)."
echo "[*] On the lab host, finish with:"
echo "    scp .env ${LAB_SSH_USER}@${LAB_SSH_HOST}:${LAB_REMOTE_DIR}/.env   # once, manually"
echo "    ssh ${LAB_SSH_USER}@${LAB_SSH_HOST} 'cd $LAB_REMOTE_DIR && bash scripts/lab-bootstrap-remote.sh'"
