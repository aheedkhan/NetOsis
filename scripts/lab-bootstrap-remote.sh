#!/usr/bin/env bash
# Run ON a honeypot CT (as root) inside a git clone at /opt/netosis.
# Creates venv, installs deps, writes .env for this honeypot, installs systemd unit.
#
#   git clone https://github.com/aheedkhan/NetOsis.git /opt/netosis
#   bash /opt/netosis/scripts/lab-bootstrap-remote.sh ent-web-01
#
# Profiles: ent-web-01 | finance-db-01 | ops-app-01 (alias: ops-srv-01)
# Re-running is safe (use after `git pull`). Existing .env is kept unless --force-env.
#
# Telemetry to the SOC: give this node ITS OWN key (python3 scripts/node_keys.py on the SOC VM):
#   NETOSIS_NODE_KEY=<key> bash scripts/lab-bootstrap-remote.sh ent-web-01
#   printf '%s\n' <key> | bash scripts/lab-bootstrap-remote.sh ent-web-01 --key-stdin   (key not in ps/history)
# scripts/lab-rollout.sh does all of this from the Proxmox host for every CT.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PROFILE="${1:-}"
FORCE_ENV=0
KEY_STDIN=0
for arg in "${@:2}"; do
  case "$arg" in
    --force-env) FORCE_ENV=1 ;;
    --key-stdin) KEY_STDIN=1 ;;
    *) echo "[!] unknown option: $arg" >&2; exit 1 ;;
  esac
done
if [[ "$KEY_STDIN" == "1" ]]; then IFS= read -r NETOSIS_NODE_KEY || true; fi
NETOSIS_NODE_KEY="${NETOSIS_NODE_KEY:-}"

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

set_env() {  # set_env KEY VALUE  -> replace or append in .env
  if grep -q "^$1=" "$ROOT/.env"; then sed -i "s|^$1=.*|$1=$2|" "$ROOT/.env"; else echo "$1=$2" >> "$ROOT/.env"; fi
}
# the ingest port moved from :8000 (now dashboard only) to :8001
sed -i 's|^\(NETOSIS_CONTROLLER_URL=http://[^:]*\):8000$|\1:8001|' "$ROOT/.env"
[[ -n "${NETOSIS_CONTROLLER_URL:-}" ]] && set_env NETOSIS_CONTROLLER_URL "$NETOSIS_CONTROLLER_URL"
set_env NETOSIS_NODE_NAME "$PROFILE"
if [[ -n "$NETOSIS_NODE_KEY" ]]; then
  [[ "$NETOSIS_NODE_KEY" =~ ^[0-9a-f]{64}$ ]] || { echo "[!] NETOSIS_NODE_KEY must be 64 hex chars" >&2; exit 1; }
  set_env NETOSIS_NODE_KEY "$NETOSIS_NODE_KEY"
  echo "[*] Set this node's signing key in .env"
fi
if grep -qE '^NETOSIS_NODE_KEY=[0-9a-f]{64}$' "$ROOT/.env"; then
  # this node no longer needs the lab-wide secret: never leave it on a honeypot
  sed -i '/^NETOSIS_INGEST_TOKEN=/d' "$ROOT/.env"
else
  echo "[!] no NETOSIS_NODE_KEY — this honeypot will not appear on the SOC dashboard."
  echo "    On the SOC VM:  python3 /opt/netosis/scripts/node_keys.py $PROFILE"
  echo "    Then:           NETOSIS_NODE_KEY=<key> bash $0 $PROFILE"
fi

mkdir -p "$ROOT/data"
chown -R netosis:netosis "$ROOT/data" "$ROOT/.env"
chmod 600 "$ROOT/.env"

install -m 0644 "$ROOT/ops/logrotate/netosis" /etc/logrotate.d/netosis

install -m 0644 "$ROOT/ops/systemd/netosis-ssh.service" /etc/systemd/system/netosis-ssh.service
systemctl daemon-reload
systemctl enable netosis-ssh.service >/dev/null
systemctl restart netosis-ssh.service
sleep 2
systemctl --no-pager --lines=15 status netosis-ssh.service || true

# Node agent: live CPU/mem/connections for the SOC's network view (outbound only)
case "$PROFILE" in ent-web-01) CTID=102 ;; finance-db-01) CTID=104 ;; ops-app-01) CTID=105 ;; esac
NETOSIS_NODE_KEY="$(grep -E '^NETOSIS_NODE_KEY=' "$ROOT/.env" | cut -d= -f2- || true)" \
NETOSIS_CONTROLLER_URL="$(grep -E '^NETOSIS_CONTROLLER_URL=' "$ROOT/.env" | cut -d= -f2-)" \
  bash "$ROOT/scripts/agent-install.sh" "$PROFILE" honeypot "$CTID" || echo "[!] agent install failed (honeypot still runs)"

LLM_URL="$(grep -E '^NETOSIS_LLM_BASE_URL=' "$ROOT/.env" | cut -d= -f2-)"
echo
echo "[+] netosis-ssh running for profile $PROFILE"
echo "    Logs:        journalctl -u netosis-ssh -f      (attacker events: $ROOT/data/telemetry.jsonl)"
echo "    Verify:      bash $ROOT/scripts/lab-verify.sh"
echo "    Local test:  ssh admin@127.0.0.1 -p 2222   (password admin123)"
echo "    LLM target:  ${LLM_URL:-unset}"
if [[ -n "$LLM_URL" ]] && ! curl -fsS -m 5 "${LLM_URL%/v1}/api/tags" >/dev/null 2>&1; then
  echo "[!] LLM not reachable yet — unknown commands will answer 'command not found'."
fi
