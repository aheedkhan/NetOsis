#!/usr/bin/env bash
# Run ON the SOC VM (192.168.40.31) as root, inside the clone at /opt/netosis.
# Installs the controller + dashboard as a systemd service, and writes each
# honeypot's own signing key to /root/netosis-node-keys.env (root 600) for
# scripts/lab-rollout.sh. The master secret never leaves this VM.
#
#   cd /opt/netosis && git pull
#   bash scripts/soc-dashboard-setup.sh
#
# The dashboard is pre-built and committed (soc/dist), so this VM needs no Node.
# Re-running is safe: the token and Proxmox settings in controller/.env are kept.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
[[ "$(id -u)" -eq 0 ]] || { echo "[!] run as root" >&2; exit 1; }

# Controller runs on system Python (stdlib only) plus python3-yaml for the
# Deception Engine's policy ladder (policy/rules/baseline.yml).
if ! command -v python3 >/dev/null || ! python3 -c "import yaml" 2>/dev/null; then
  apt-get update -qq && apt-get install -y -qq python3 python3-yaml >/dev/null
fi
python3 - <<'PY'
import sys
if sys.version_info < (3, 10):
    sys.exit(f"[!] Python 3.10+ required, found {sys.version.split()[0]}")
PY
[[ -f "$ROOT/soc/dist/index.html" ]] || { echo "[!] soc/dist missing — git pull, or build it on a machine with Node (cd soc && npm ci && npm run build)" >&2; exit 1; }

id -u netosis >/dev/null 2>&1 || useradd --system --home "$ROOT" --shell /usr/sbin/nologin netosis

ENV="$ROOT/controller/.env"
if [[ ! -f "$ENV" ]]; then
  TOKEN="$(python3 -c 'import secrets; print(secrets.token_hex(24))')"
  cat > "$ENV" <<EOT
# NetOsis controller settings (never commit this file)
NETOSIS_INGEST_TOKEN=$TOKEN
NETOSIS_CONTROLLER_PORT=8000
NETOSIS_INGEST_PORT=8001
NETOSIS_REQUIRE_SIGNED=1
NETOSIS_NODES=ent-web-01,finance-db-01,ops-app-01,controller

# Global attack map (optional). Arcs end at the lab's real location; without
# these, live sources are still listed but no arcs are drawn.
NETOSIS_SITE_LAT=
NETOSIS_SITE_LNG=
NETOSIS_SITE_LABEL=NetOsis lab
# Public-IP geolocation (optional): put GeoLite2-City.mmdb in data/geoip/ and
# apt install python3-maxminddb. Private/lab IPs are never geolocated.

# Honeypot auto-wake: restricted Proxmox API token (see ops/SERVER_RUNBOOK.md step 1b).
# Leave blank until you have it — the dashboard and telemetry work without it.
PROXMOX_HOST=172.30.226.7:8006
PROXMOX_NODE=vhos
PROXMOX_TOKEN_ID=
PROXMOX_TOKEN_SECRET=
PROXMOX_VERIFY_SSL=0
EOT
  echo "[*] Generated controller/.env with a new ingest token"
else
  echo "[*] Keeping existing controller/.env"
  # settings added later: append only what is missing, never touch the secrets
  for kv in NETOSIS_INGEST_PORT=8001 NETOSIS_REQUIRE_SIGNED=1 NETOSIS_NODES=ent-web-01,finance-db-01,ops-app-01,controller; do
    grep -q "^${kv%%=*}=" "$ENV" || { echo "$kv" >> "$ENV"; echo "[*] Added ${kv%%=*} to controller/.env"; }
  done
fi
mkdir -p "$ROOT/data/soc"
chown -R netosis:netosis "$ROOT/data" "$ENV"
chmod 600 "$ENV"

install -m 0644 "$ROOT/ops/logrotate/netosis" /etc/logrotate.d/netosis
install -d /etc/systemd/journald.conf.d
install -m 0644 "$ROOT/ops/journald/netosis.conf" /etc/systemd/journald.conf.d/netosis.conf
systemctl restart systemd-journald || true
# signatures carry a timestamp: the SOC VM's clock must be right
timedatectl set-ntp true 2>/dev/null || true

install -m 0644 "$ROOT/ops/systemd/netosis-controller.service" /etc/systemd/system/netosis-controller.service
systemctl daemon-reload
systemctl enable netosis-controller.service >/dev/null
systemctl restart netosis-controller.service
sleep 2
systemctl --no-pager --lines=8 status netosis-controller.service || true

bash "$ROOT/scripts/agent-install.sh" controller soc || echo "[!] agent install failed (dashboard still runs)"

KEYS=/root/netosis-node-keys.env
( umask 077; python3 "$ROOT/scripts/node_keys.py" --env ent-web-01 finance-db-01 ops-app-01 > "$KEYS" )
IP="$(hostname -I | awk '{print $1}')"
echo
for p in 8000 8001; do
  if curl -fsS -m 5 "http://127.0.0.1:$p/healthz" >/dev/null; then echo "[+] controller up on :$p"
  else echo "[!] controller not answering on :$p — journalctl -u netosis-controller -n 30"; fi
done
echo "    Dashboard:   http://${IP:-192.168.40.31}:8000/   (Jbox only — see docs/DEPLOY-lab.md firewall rules)"
echo "    Ingest:      http://${IP:-192.168.40.31}:8001/   (honeypot VLANs only; signed requests)"
echo "    Logs:        journalctl -u netosis-controller -f    events: $ROOT/data/soc/events.jsonl"
echo
echo "    Node keys written to $KEYS (root 600). Copy that file to the Proxmox host"
echo "    as /root/netosis-node-keys.env, then run there:  bash scripts/lab-rollout.sh"
echo "    (each CT gets only its own key; delete the copy afterwards)"
echo
echo "    Fill the dashboard without waiting for attackers (rehearsal / viva):"
echo "      python3 scripts/soc_demo.py --controller http://127.0.0.1:8000 --speed 2"