#!/usr/bin/env bash
# Install the NetOsis node agent on this machine (run as root, inside the clone).
#
#   NETOSIS_NODE_KEY=<key> bash scripts/agent-install.sh <node-name> [role] [ctid]
#
#   bash scripts/agent-install.sh ent-web-01    honeypot 102
#   bash scripts/agent-install.sh finance-db-01 honeypot 104
#   bash scripts/agent-install.sh ops-app-01    honeypot 105
#   bash scripts/agent-install.sh controller    soc        (on the SOC VM; key derived from controller/.env)
#
# The key is this node's own signing key (python3 scripts/node_keys.py <name> on
# the SOC VM). The agent only makes signed outbound POSTs; it opens no port.
# Optional: NETOSIS_CONTROLLER_URL (default http://192.168.40.31:8001, the ingest port).
# Re-running is safe: updates the agent code and settings, keeps the key if none is given.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ "$(id -u)" -eq 0 ]] || { echo "[!] run as root" >&2; exit 1; }

NAME="${1:-}"
ROLE="${2:-other}"
CTID="${3:-}"
[[ -n "$NAME" ]] || { echo "Usage: $0 <node-name> [honeypot|soc|other] [ctid]" >&2; exit 1; }
[[ "$NAME" =~ ^[A-Za-z0-9._-]{1,64}$ ]] || { echo "[!] bad node name" >&2; exit 1; }
[[ -z "$CTID" || "$CTID" =~ ^[0-9]+$ ]] || { echo "[!] ctid must be a number" >&2; exit 1; }
command -v python3 >/dev/null || { apt-get update -qq && apt-get install -y -qq python3 >/dev/null; }

case "$ROLE" in
  honeypot) SERVICES="netosis-ssh" ;;
  soc)      SERVICES="netosis-controller,ollama" ;;
  *)        SERVICES="" ;;
esac

ENVF=/etc/netosis/agent.env
KEY="${NETOSIS_NODE_KEY:-}"
URL="${NETOSIS_CONTROLLER_URL:-}"
if [[ -z "$KEY" && -f "$ENVF" ]]; then KEY="$(grep -E '^NETOSIS_NODE_KEY=' "$ENVF" | cut -d= -f2- || true)"; fi
if [[ -z "$KEY" && "$ROLE" == "soc" && -f "$ROOT/controller/.env" ]]; then
  KEY="$(python3 "$ROOT/scripts/node_keys.py" --env "$NAME" | cut -d= -f2-)"
fi
if [[ -z "$URL" && -f "$ENVF" ]]; then URL="$(grep -E '^NETOSIS_CONTROLLER_URL=' "$ENVF" | cut -d= -f2- | sed 's|:8000$|:8001|' || true)"; fi
if [[ -z "$URL" && "$ROLE" == "soc" ]]; then URL="http://127.0.0.1:8001"; fi
URL="${URL:-http://192.168.40.31:8001}"
[[ "$KEY" =~ ^[0-9a-f]{64}$ ]] || { echo "[!] no valid NETOSIS_NODE_KEY (64 hex): get it with  python3 scripts/node_keys.py $NAME  on the SOC VM" >&2; exit 1; }

id -u netosis-agent >/dev/null 2>&1 || useradd --system --no-create-home --home /nonexistent --shell /usr/sbin/nologin netosis-agent

install -d -m 0755 -o root -g root /usr/local/lib/netosis-agent
install -m 0644 -o root -g root "$ROOT/agent/netosis_agent.py" /usr/local/lib/netosis-agent/netosis_agent.py

install -d -m 0700 -o root -g root /etc/netosis
umask 077
cat > "$ENVF" <<EOT
# NetOsis node agent (root-only; read by systemd, never by the honeypot)
NETOSIS_CONTROLLER_URL=$URL
NETOSIS_NODE_KEY=$KEY
NETOSIS_NODE_NAME=$NAME
NETOSIS_NODE_ROLE=$ROLE
NETOSIS_NODE_CTID=$CTID
NETOSIS_AGENT_SERVICES=$SERVICES
NETOSIS_AGENT_INTERVAL=10
EOT
chown root:root "$ENVF"
chmod 600 "$ENVF"

install -m 0644 "$ROOT/ops/systemd/netosis-agent.service" /etc/systemd/system/netosis-agent.service
DROPIN=/etc/systemd/system/netosis-agent.service.d
install -d "$DROPIN"
install -m 0644 "$ROOT/ops/systemd/netosis-agent-seccomp.conf" "$DROPIN/seccomp.conf"

start_agent() {
  systemctl daemon-reload
  systemctl reset-failed netosis-agent.service 2>/dev/null || true
  systemctl enable netosis-agent.service >/dev/null
  systemctl restart netosis-agent.service 2>/dev/null || true
  sleep 3
  systemctl is-active --quiet netosis-agent.service
}
HARDENING="full"
if ! start_agent; then
  # this container can't load seccomp filters: keep the rest of the hardening
  rm -f "$DROPIN/seccomp.conf"
  HARDENING="base (no seccomp: this container doesn't allow it)"
  start_agent || true
fi
if systemctl is-active --quiet netosis-agent.service; then
  echo "[+] netosis-agent running: $NAME ($ROLE) -> $URL every 10 s (signed, hardening: $HARDENING)"
else
  echo "[!] netosis-agent failed to start:"
  systemctl --no-pager --lines=15 status netosis-agent.service || true
fi
echo "    Logs:  journalctl -u netosis-agent -f"
echo "    Check: no listening socket ->  ss -ltnp | grep -c netosis_agent  (expect 0)"
