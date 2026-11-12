#!/usr/bin/env bash
# Install / update NetOsis on every honeypot CT, from the Proxmox host (as root).
#
#   git clone https://github.com/aheedkhan/NetOsis.git /root/netosis     # once, on the host
#   cd /root/netosis && git pull
#   bash scripts/lab-rollout.sh                      # CT102, CT104, CT105
#   bash scripts/lab-rollout.sh --only 104           # one CT
#   bash scripts/lab-rollout.sh --verify-only        # just run the checks
#
# Needs /root/netosis-node-keys.env from the SOC VM (scripts/soc-dashboard-setup.sh
# writes it there). Override with --keys FILE.
#
# How it works, and why it needs no new network path:
#   * The code goes in with `pct push` (host -> CT filesystem), not git or SSH,
#     so the CTs need no SSH server and no route to GitHub.
#   * Each CT's key goes in on stdin of `pct exec`, so it never appears in a
#     process list, shell history or file on the host besides the keys file.
#   * Each CT gets only its own key, never the controller's master secret.
#   * apt/pip inside the CT still need Internet the first time (see
#     docs/DEPLOY-lab.md: open it for the install, then close it).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KEYS=/root/netosis-node-keys.env
ONLY=""
VERIFY_ONLY=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --keys) KEYS="$2"; shift 2 ;;
    --only) ONLY="$2"; shift 2 ;;
    --verify-only) VERIFY_ONLY=1; shift ;;
    -h|--help) sed -n '2,21p' "$0"; exit 0 ;;
    *) echo "[!] unknown option: $1" >&2; exit 1 ;;
  esac
done

[[ "$(id -u)" -eq 0 ]] || { echo "[!] run as root on the Proxmox host" >&2; exit 1; }
command -v pct >/dev/null || { echo "[!] pct not found: run this on the Proxmox host" >&2; exit 1; }

# CTID -> honeypot profile (same as controller/app.py ALLOWED_CTIDS)
declare -A PROFILE=([102]=ent-web-01 [104]=finance-db-01 [105]=ops-app-01)
CTIDS=(102 104 105)
if [[ -n "$ONLY" ]]; then
  [[ -n "${PROFILE[$ONLY]:-}" ]] || { echo "[!] --only must be one of ${CTIDS[*]}" >&2; exit 1; }
  CTIDS=("$ONLY")
fi

if [[ "$VERIFY_ONLY" == "0" ]]; then
  [[ -f "$KEYS" ]] || { echo "[!] $KEYS missing — copy it from the SOC VM (/root/netosis-node-keys.env)" >&2; exit 1; }
  [[ "$(stat -c %a "$KEYS")" == "600" ]] || { chmod 600 "$KEYS"; echo "[*] tightened $KEYS to 600"; }
  [[ -d "$ROOT/.git" ]] || { echo "[!] run from a git clone (git archive packs the committed code)" >&2; exit 1; }
  TAR="$(mktemp /root/netosis-src.XXXXXX.tar.gz)"
  trap 'rm -f "$TAR"' EXIT
  git -C "$ROOT" archive --format=tar.gz -o "$TAR" HEAD
  echo "[*] packed $(git -C "$ROOT" rev-parse --short HEAD) ($(du -h "$TAR" | cut -f1))"
fi

ensure_running() {
  local ct="$1"
  if [[ "$(pct status "$ct" | awk '{print $2}')" != "running" ]]; then
    echo "    starting CT$ct"
    pct start "$ct"
    for _ in $(seq 1 30); do
      pct exec "$ct" -- true 2>/dev/null && return 0
      sleep 1
    done
    echo "[!] CT$ct did not come up" >&2
    return 1
  fi
}

declare -A RESULT
for ct in "${CTIDS[@]}"; do
  prof="${PROFILE[$ct]}"
  echo
  echo "=== CT$ct  $prof ==="
  if ! pct config "$ct" >/dev/null 2>&1; then
    echo "[!] CT$ct does not exist"; RESULT[$ct]="missing"; continue
  fi
  pct config "$ct" | grep -E '^net[0-9]+:' | grep -q 'firewall=1' \
    || echo "[!] CT$ct NIC has no firewall=1 (Proxmox firewall won't filter it) — add it in the GUI"
  ensure_running "$ct" || { RESULT[$ct]="not running"; continue; }

  if [[ "$VERIFY_ONLY" == "0" ]]; then
    key="$(grep -E "^${prof}=" "$KEYS" | cut -d= -f2- || true)"
    [[ "$key" =~ ^[0-9a-f]{64}$ ]] || { echo "[!] no key for $prof in $KEYS"; RESULT[$ct]="no key"; continue; }
    pct push "$ct" "$TAR" /root/netosis-src.tar.gz --perms 600
    # unpack over /opt/netosis: keeps .env, .venv and data/ (not in the archive)
    pct exec "$ct" -- bash -c 'set -e; mkdir -p /opt/netosis; tar -xzf /root/netosis-src.tar.gz -C /opt/netosis; rm -f /root/netosis-src.tar.gz'
    if ! printf '%s\n' "$key" | pct exec "$ct" -- bash /opt/netosis/scripts/lab-bootstrap-remote.sh "$prof" --key-stdin; then
      RESULT[$ct]="install failed"; continue
    fi
  fi
  if pct exec "$ct" -- bash /opt/netosis/scripts/lab-verify.sh; then RESULT[$ct]="ok"; else RESULT[$ct]="checks failed"; fi
done

echo
echo "=== summary ==="
for ct in "${CTIDS[@]}"; do printf '  CT%-4s %-14s %s\n' "$ct" "${PROFILE[$ct]}" "${RESULT[$ct]:-skipped}"; done
[[ "$VERIFY_ONLY" == "1" ]] || echo "  When all are ok: rm $KEYS   (the CTs hold their own copies)"
