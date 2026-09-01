#!/usr/bin/env bash
# Lab verification. Needs only podman on the host (plus bash).
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

VERIFY_IMG=localhost/cybersnare-verify:lab
FAILS=0

ok() { printf '  OK    %s\n' "$*"; }
bad() { printf '  FAIL  %s\n' "$*"; FAILS=$((FAILS + 1)); }

if ! command -v podman >/dev/null 2>&1; then
  echo "podman is required on the host." >&2
  exit 1
fi

if ! podman image exists "$VERIFY_IMG" 2>/dev/null; then
  echo "Building verify image..."
  podman build -t "$VERIFY_IMG" -f containers/Dockerfile.verify . || exit 1
fi

echo "== isolation (sandbox must not reach mgmt or the internet) =="
if podman exec cs-sandbox python -c "import socket; socket.create_connection(('10.200.1.10', 8088), 3).close()" 2>/dev/null; then
  bad "sandbox reached logger on mgmt — containment broken"
else
  ok "sandbox cannot reach logger (10.200.1.10)"
fi
if podman exec cs-sandbox python -c "import socket; socket.create_connection(('1.1.1.1', 80), 3).close()" 2>/dev/null; then
  bad "sandbox reached 1.1.1.1 — internal network is leaking"
else
  ok "sandbox cannot reach 1.1.1.1"
fi

echo "== sinkhole stage 0 =="
RESOLVE="$(podman exec cs-sandbox python -c "import socket; print(socket.getaddrinfo('malware.example', 80)[0][4][0])" 2>/dev/null || true)"
if printf '%s' "$RESOLVE" | grep -q '10.200.3.2'; then
  ok "DNS sinkhole returns 10.200.3.2"
else
  bad "DNS sinkhole did not return 10.200.3.2 (${RESOLVE})"
fi
PAYLOAD="$(podman exec cs-sandbox python -c "import urllib.request; print(urllib.request.urlopen('http://malware.example/payload.sh', timeout=3).read().decode())" 2>/dev/null || true)"
if printf '%s' "$PAYLOAD" | grep -q sinkholed; then
  ok "HTTP sinkhole served a neutered payload"
else
  bad "HTTP sinkhole fetch failed"
fi
sleep 2

INNER_FAILS=0
podman run --rm --network host "$VERIFY_IMG" || INNER_FAILS=$?
FAILS=$((FAILS + INNER_FAILS))

echo
if [ "$FAILS" -eq 0 ]; then
  echo "Lab is up."
  exit 0
fi
echo "$FAILS check(s) failed."
exit 1
