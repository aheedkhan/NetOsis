#!/usr/bin/env bash
# Runs inside the verify container (--network host). Host-side isolation checks live in verify.sh.
set -u

FAILS=0

ok() { printf '  OK    %s\n' "$*"; }
bad() { printf '  FAIL  %s\n' "$*"; FAILS=$((FAILS + 1)); }

echo "== health =="
if curl -sf --max-time 3 http://127.0.0.1:18088/health >/dev/null; then
  ok "logger on 127.0.0.1:18088"
else
  bad "logger not healthy"
fi
if curl -sf --max-time 3 http://127.0.0.1:19000/health >/dev/null; then
  ok "decision on 127.0.0.1:19000"
else
  bad "decision not healthy"
fi

echo "== surfaces (localhost only) =="
if ! curl -sf --max-time 2 http://127.0.0.1:8080/ >/dev/null 2>&1; then
  ok "HTTP disabled on 127.0.0.1:8080 (HTTPS-only posture)"
else
  bad "plaintext HTTP still reachable on 127.0.0.1:8080"
fi

HTTPS_BODY="$(curl -skf --max-time 5 https://127.0.0.1:8443/ || true)"
if printf '%s' "$HTTPS_BODY" | grep -q NexusCorp; then
  ok "HTTPS portal on 127.0.0.1:8443"
else
  bad "HTTPS portal did not respond"
fi
LOGIN="$(curl -sk --max-time 3 -o /dev/null -w '%{http_code}' -X POST https://127.0.0.1:8443/login -d 'username=admin&password=admin')"
if [ "$LOGIN" = "401" ]; then
  ok "HTTPS login closed (401)"
else
  bad "HTTPS login expected 401, got ${LOGIN:-none}"
fi

BANNER="$(python3 - <<'PY'
import socket
s = socket.create_connection(("127.0.0.1", 2222), timeout=3)
s.settimeout(3)
data = s.recv(256)
s.close()
print(data.decode("latin1", errors="replace").strip().splitlines()[0])
PY
)"
if printf '%s' "$BANNER" | grep -q 'SSH-2.0-OpenSSH'; then
  ok "SSH banner on 127.0.0.1:2222 (${BANNER})"
else
  bad "SSH banner missing (${BANNER})"
fi

SSH_OUT="$(ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  -o ConnectTimeout=5 -p 2222 nobody@127.0.0.1 true 2>&1 || true)"
if printf '%s' "$SSH_OUT" | grep -Eqi 'permission denied|authentication failed'; then
  ok "SSH KEX completed and auth refused"
else
  bad "SSH KEX/auth check failed (${SSH_OUT})"
fi

echo "== waiting for Zeek flush =="
# Zeek finalises conn.log (and the protocol-specific logs) when it sees the
# connection close, not on a fixed timer, and the observed flush latency in
# this environment ranged from about 5s to 15s. A blind sleep either wastes
# time or occasionally loses the race, so this polls the logger's own tail
# instead of guessing a fixed delay: it moves on as soon as a Zeek-derived
# event actually shows up, and only gives up after a generous ceiling.
ZEEK_WAIT_S="${CS_VERIFY_ZEEK_WAIT_S:-30}"
elapsed=0
zeek_seen=""
while [ "$elapsed" -lt "$ZEEK_WAIT_S" ]; do
  zeek_seen="$(python3 -c "
import json, urllib.request
try:
    raw = urllib.request.urlopen('http://127.0.0.1:18088/v1/tail?n=200', timeout=3).read()
    lines = json.loads(raw).get('lines', [])
    ds = {e.get('event', {}).get('dataset') for e in lines}
    print('yes' if any(d and d.startswith('cybersnare.zeek.') for d in ds) else '')
except Exception:
    print('')
" 2>/dev/null)"
  [ -n "$zeek_seen" ] && break
  sleep 2
  elapsed=$((elapsed + 2))
done
echo "  (waited ${elapsed}s)"

echo "== telemetry =="
python3 - <<'PY'
import json, sys, urllib.request
raw = urllib.request.urlopen("http://127.0.0.1:18088/v1/tail?n=200", timeout=5).read()
data = json.loads(raw)
lines = data.get("lines", [])
datasets = {e.get("event", {}).get("dataset") for e in lines}
needed = {
    "cybersnare.http.request",
    "cybersnare.sinkhole.dns",
    "cybersnare.sinkhole.http",
}
missing = sorted(needed - datasets)
open("/tmp/cs-verify-missing", "w").write("\n".join(missing))
zeekish = {d for d in datasets if d and d.startswith("cybersnare.zeek.")}
open("/tmp/cs-verify-zeek", "w").write("\n".join(sorted(zeekish)))
fp = False
for e in lines:
    net = e.get("network") or {}
    if net.get("hassh") or net.get("ja4"):
        fp = True
        break
open("/tmp/cs-verify-fp", "w").write("yes" if fp else "no")
sys.exit(1 if missing else 0)
PY
MISSING_RC=$?
if [ "$MISSING_RC" -eq 0 ]; then
  ok "JSONL has HTTP and sinkhole events"
else
  miss="$(cat /tmp/cs-verify-missing 2>/dev/null | tr '\n' ' ')"
  bad "missing datasets: ${miss}"
fi
if [ -s /tmp/cs-verify-zeek ]; then
  ok "JSONL has Zeek datasets ($(tr '\n' ' ' </tmp/cs-verify-zeek))"
else
  bad "no cybersnare.zeek.* events in the log"
fi
if [ "$(cat /tmp/cs-verify-fp 2>/dev/null)" = "yes" ]; then
  ok "at least one event carries HASSH or JA4"
else
  bad "no network.hassh or network.ja4 in recent events"
fi

if curl -sf --max-time 3 http://127.0.0.1:19000/v1/manifest | grep -q 'p0-static-v1'; then
  ok "decision plane still on P0 static manifest"
else
  bad "P0 manifest not published"
fi

exit "$FAILS"
