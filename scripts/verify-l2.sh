#!/usr/bin/env bash
# L2 engage smoke test — requires gate passed and ./cs set-level L2.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FAILS=0

ok() { printf '  OK    %s\n' "$*"; }
bad() { printf '  FAIL  %s\n' "$*"; FAILS=$((FAILS + 1)); }

echo "== L2 engage smoke test =="

MANIFEST="$(curl -sf --max-time 3 http://127.0.0.1:19000/v1/manifest 2>/dev/null || true)"
if printf '%s' "$MANIFEST" | grep -q '"auth": "open"'; then
  ok "manifest has auth open"
else
  bad "manifest auth not open — run: ./cs set-level L2"
fi

OUT="$(podman run --rm --network host docker.io/library/alpine:3.21 sh -c \
  "apk add -q openssh-client sshpass >/dev/null && sshpass -p 'nexus2024' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -p 2222 guest@127.0.0.1 whoami" 2>&1 || true)"
if printf '%s' "$OUT" | grep -q guest; then
  ok "SSH restricted shell accepts guest credentials"
else
  # Fallback without sshpass: expect auth path reachable
  if printf '%s' "$OUT" | grep -Eqi 'permission denied|authentication failed|password'; then
    bad "SSH auth failed (${OUT}) — check config/shell-users.json"
  else
    bad "SSH L2 session failed (${OUT})"
  fi
fi

if curl -sk --max-time 3 -o /dev/null -w '%{http_code}' -X POST https://127.0.0.1:8443/login \
  -d 'username=guest&password=nexus2024' | grep -q 200; then
  ok "HTTPS login accepts guest when auth open"
else
  bad "HTTPS guest login did not return 200"
fi

echo
if [ "$FAILS" -eq 0 ]; then
  echo "L2 engage OK."
  exit 0
fi
echo "$FAILS L2 check(s) failed."
exit 1
