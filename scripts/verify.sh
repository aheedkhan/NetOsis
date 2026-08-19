#!/usr/bin/env bash
# Scope B: Scope A checks, plus KEX-refused SSH, HTTPS, Zeek fingerprints.
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
HTTP_BODY="$(curl -sf --max-time 3 http://127.0.0.1:8080/ || true)"
if printf '%s' "$HTTP_BODY" | grep -q NexusCorp; then
  ok "HTTP portal on 127.0.0.1:8080"
else
  bad "HTTP portal did not respond"
fi
LOGIN="$(curl -s --max-time 3 -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:8080/login -d 'username=admin&password=admin')"
if [ "$LOGIN" = "401" ]; then
  ok "HTTP login closed (401)"
else
  bad "HTTP login expected 401, got ${LOGIN:-none}"
fi

HTTPS_BODY="$(curl -skf --max-time 5 https://127.0.0.1:8443/ || true)"
if printf '%s' "$HTTPS_BODY" | grep -q NexusCorp; then
  ok "HTTPS portal on 127.0.0.1:8443"
else
  bad "HTTPS portal did not respond"
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

echo "== waiting for Zeek flush =="
sleep 4

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

echo
if [ "$FAILS" -eq 0 ]; then
  echo "Scope B lab is up."
  exit 0
fi
echo "$FAILS check(s) failed."
exit 1
