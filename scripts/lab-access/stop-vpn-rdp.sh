#!/usr/bin/env bash
# Stop FreeRDP jump box and OpenVPN using PID files from environment / .env.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
if [[ -f "$ROOT/.env" ]]; then
  # shellcheck disable=SC1091
  set -a
  source "$ROOT/.env"
  set +a
fi

VPN_PID_PATH="${VPN_PID_PATH:-$HOME/Documents/server/openvpn.pid}"
RDP_PID_PATH="${RDP_PID_PATH:-$HOME/Documents/server/jumpbox-rdp.pid}"

if [[ -f "$RDP_PID_PATH" ]]; then
  RDP_PID="$(cat "$RDP_PID_PATH")"
  if kill -0 "$RDP_PID" 2>/dev/null; then
    echo "[+] Stopping FreeRDP PID $RDP_PID"
    kill "$RDP_PID" || true
  fi
  rm -f "$RDP_PID_PATH"
else
  echo "[*] No FreeRDP PID file"
fi

if [[ -f "$VPN_PID_PATH" ]]; then
  VPN_PID="$(cat "$VPN_PID_PATH")"
  if kill -0 "$VPN_PID" 2>/dev/null; then
    echo "[+] Stopping OpenVPN PID $VPN_PID (may need sudo)"
    sudo kill "$VPN_PID" || kill "$VPN_PID" || true
  fi
  rm -f "$VPN_PID_PATH"
else
  echo "[*] No OpenVPN PID file"
fi

echo "[+] Done"
