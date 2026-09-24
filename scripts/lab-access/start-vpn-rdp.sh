#!/usr/bin/env bash
# Start OpenVPN + FreeRDP jump box using paths from environment / .env.
# Does not embed secrets. Prefer the user's existing start.sh if present.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
if [[ -f "$ROOT/.env" ]]; then
  # shellcheck disable=SC1091
  set -a
  source "$ROOT/.env"
  set +a
fi

VPN_CONFIG_PATH="${VPN_CONFIG_PATH:-$HOME/Documents/server/Aheed_VPN_aheed.ovpn}"
VPN_LOG_PATH="${VPN_LOG_PATH:-$HOME/Documents/server/openvpn.log}"
VPN_PID_PATH="${VPN_PID_PATH:-$HOME/Documents/server/openvpn.pid}"
RDP_SCRIPT_PATH="${RDP_SCRIPT_PATH:-$HOME/.config/freerdp/jumpbox.sh}"
RDP_PID_PATH="${RDP_PID_PATH:-$HOME/Documents/server/jumpbox-rdp.pid}"
LEGACY_START="${LEGACY_START:-$HOME/Documents/server/start.sh}"

if [[ -x "$LEGACY_START" ]]; then
  echo "[*] Delegating to existing launcher: $LEGACY_START"
  exec "$LEGACY_START"
fi

if [[ ! -f "$VPN_CONFIG_PATH" ]]; then
  echo "[!] VPN config not found: $VPN_CONFIG_PATH" >&2
  exit 1
fi

if [[ -f "$VPN_PID_PATH" ]]; then
  OLD_PID="$(cat "$VPN_PID_PATH")"
  if kill -0 "$OLD_PID" 2>/dev/null; then
    echo "[+] OpenVPN already running (PID $OLD_PID)"
  else
    rm -f "$VPN_PID_PATH"
  fi
fi

if [[ ! -f "$VPN_PID_PATH" ]]; then
  echo "[+] Starting OpenVPN..."
  sudo openvpn --config "$VPN_CONFIG_PATH" >"$VPN_LOG_PATH" 2>&1 &
  echo $! >"$VPN_PID_PATH"
fi

echo "[+] Waiting for tun0..."
for _ in $(seq 1 20); do
  if ip link show tun0 >/dev/null 2>&1; then
    echo "[+] tun0 is UP"
    break
  fi
  sleep 1
done

if ! ip link show tun0 >/dev/null 2>&1; then
  echo "[!] VPN tunnel did not come up. See $VPN_LOG_PATH" >&2
  exit 1
fi

if [[ ! -x "$RDP_SCRIPT_PATH" ]]; then
  echo "[!] FreeRDP script missing or not executable: $RDP_SCRIPT_PATH" >&2
  exit 1
fi

echo "[+] Starting Jump Box FreeRDP..."
"$RDP_SCRIPT_PATH" &
echo $! >"$RDP_PID_PATH"
echo "[+] Jump box target (info): ${JUMPBOX_RDP_TARGET:-172.30.227.1}"
echo "[+] OpenVPN PID: $(cat "$VPN_PID_PATH")"
echo "[+] FreeRDP PID: $(cat "$RDP_PID_PATH")"
