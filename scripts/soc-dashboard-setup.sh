#!/usr/bin/env bash
# Run ON the SOC VM (192.168.40.31) as root, inside the clone at /opt/netosis.
# Installs the controller + dashboard as a systemd service and prints the one
# secret the honeypots need (the ingest token).
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
fi
mkdir -p "$ROOT/data/soc"
chown -R netosis:netosis "$ROOT/data" "$ENV"
chmod 600 "$ENV"

install -m 0644 "$ROOT/ops/systemd/netosis-controller.service" /etc/systemd/system/netosis-controller.service
systemctl daemon-reload
systemctl enable netosis-controller.service >/dev/null
systemctl restart netosis-controller.service
sleep 2
systemctl --no-pager --lines=8 status netosis-controller.service || true

bash "$ROOT/scripts/agent-install.sh" controller soc || echo "[!] agent install failed (dashboard still runs)"

TOKEN="$(grep -E '^NETOSIS_INGEST_TOKEN=' "$ENV" | cut -d= -f2-)"
IP="$(hostname -I | awk '{print $1}')"
echo
if curl -fsS -m 5 "http://127.0.0.1:8000/healthz" >/dev/null; then
  echo "[+] controller up"
else
  echo "[!] controller not answering on :8000 — journalctl -u netosis-controller -n 30"
fi
echo "    Dashboard:   http://${IP:-192.168.40.31}:8000/   (open from the Jbox browser)"
echo "    Logs:        journalctl -u netosis-controller -f"
echo
echo "    Give every honeypot this token (CT102, CT104, CT105), then restart it:"
echo "      NETOSIS_INGEST_TOKEN=$TOKEN bash /opt/netosis/scripts/lab-bootstrap-remote.sh <profile>"
echo
echo "    Fill the dashboard without waiting for attackers (rehearsal / viva):"
echo "      python3 scripts/soc_demo.py --controller http://127.0.0.1:8000 --token $TOKEN --speed 2"
