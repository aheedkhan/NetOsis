#!/usr/bin/env bash
# Report VPN tunnel and FreeRDP / OpenVPN process status.
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
JUMPBOX_RDP_TARGET="${JUMPBOX_RDP_TARGET:-172.30.227.1}"

echo "=== NetOsis lab access status ==="
echo "Jump box target: $JUMPBOX_RDP_TARGET"

if ip link show tun0 >/dev/null 2>&1; then
  echo "tun0: UP"
  ip -4 addr show tun0 | sed 's/^/  /' || true
else
  echo "tun0: DOWN"
fi

if [[ -f "$VPN_PID_PATH" ]]; then
  VPN_PID="$(cat "$VPN_PID_PATH")"
  if kill -0 "$VPN_PID" 2>/dev/null; then
    echo "OpenVPN: running (PID $VPN_PID)"
  else
    echo "OpenVPN: stale PID file ($VPN_PID)"
  fi
else
  echo "OpenVPN: no PID file"
fi

if [[ -f "$RDP_PID_PATH" ]]; then
  RDP_PID="$(cat "$RDP_PID_PATH")"
  if kill -0 "$RDP_PID" 2>/dev/null; then
    echo "FreeRDP: running (PID $RDP_PID)"
  else
    echo "FreeRDP: stale PID file ($RDP_PID)"
  fi
else
  echo "FreeRDP: no PID file"
fi
