#!/usr/bin/env bash
# Run ON a honeypot CT (as root) inside a git clone at /opt/netosis.
# Creates venv, installs deps, writes .env for this honeypot, installs systemd unit.
#
#   git clone https://github.com/aheedkhan/NetOsis.git /opt/netosis
#   bash /opt/netosis/scripts/lab-bootstrap-remote.sh ent-web-01
#
# Profiles: ent-web-01 | finance-db-01 | ops-app-01 (alias: ops-srv-01)
# Re-running is safe (use after `git pull`). Existing .env is kept unless --force-env.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PROFILE="${1:-}"
FORCE_ENV=0
[[ "${2:-}" == "--force-env" ]] && FORCE_ENV=1

if [[ "$(id -u)" -ne 0 ]]; then
  echo "[!] Re-run as root (needed for apt / useradd / systemd)." >&2
  exit 1
fi

case "$PROFILE" in
  ent-web-01|finance-db-01|ops-app-01) ;;
  ops-srv-01) PROFILE=ops-app-01 ;;
  *)
    echo "Usage: $0 <ent-web-01|finance-db-01|ops-app-01> [--force-env]" >&2
    exit 1
    ;;
esac
ENV_SRC="$ROOT/deception/hosts/${PROFILE}.ssh.env"

echo "[*] Installing OS packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq git curl python3 python3-venv python3-pip >/dev/null

python3 - <<'EOF'
import sys
if sys.version_info < (3, 10):
    sys.exit(f"[!] Python 3.10+ required, found {sys.version.split()[0]}")
EOF

id -u netosis >/dev/null 2>&1 || useradd --system --home "$ROOT" --shell /usr/sbin/nologin netosis

echo "[*] Python venv + requirements"
[[ -d "$ROOT/.venv" ]] || python3 -m venv "$ROOT/.venv"
"$ROOT/.venv/bin/pip" install -q -U pip
"$ROOT/.venv/bin/pip" install -q -r "$ROOT/requirements.txt"

if [[ ! -f "$ROOT/.env" || "$FORCE_ENV" == "1" ]]; then
  cp "$ENV_SRC" "$ROOT/.env"
  echo "[*] Wrote .env from $(basename "$ENV_SRC")"
else
  echo "[*] Keeping existing .env (pass --force-env to replace)"
fi

mkdir -p "$ROOT/data"
chown -R netosis:netosis "$ROOT/data" "$ROOT/.env"
chmod 600 "$ROOT/.env"

install -m 0644 "$ROOT/ops/systemd/netosis-ssh.service" /etc/systemd/system/netosis-ssh.service
systemctl daemon-reload
systemctl enable netosis-ssh.service >/dev/null
systemctl restart netosis-ssh.service
sleep 2
systemctl --no-pager --lines=15 status netosis-ssh.service || true

LLM_URL="$(grep -E '^NETOSIS_LLM_BASE_URL=' "$ROOT/.env" | cut -d= -f2-)"
echo
echo "[+] netosis-ssh running for profile $PROFILE"
echo "    Logs:        journalctl -u netosis-ssh -f"
echo "    Local test:  ssh admin@127.0.0.1 -p 2222   (password admin123)"
echo "    LLM target:  ${LLM_URL:-unset}"
if [[ -n "$LLM_URL" ]] && ! curl -fsS -m 5 "${LLM_URL%/v1}/api/tags" >/dev/null 2>&1; then
  echo "[!] LLM not reachable yet — unknown commands will answer 'command not found'."
fi
