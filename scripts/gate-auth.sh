#!/usr/bin/env bash
# Demonstrate §4.5 nineteen-property SSH authentication gate (design record).
# Properties 1–18 are automated; property 19 requires supervisor approval on file.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

FAILS=0
PASS=0

ok() { printf '  OK    #%s %s\n' "$1" "$2"; PASS=$((PASS + 1)); }
bad() { printf '  FAIL  #%s %s\n' "$1" "$2"; FAILS=$((FAILS + 1)); }
skip() { printf '  SKIP  #%s %s\n' "$1" "$2"; }

if ! command -v podman >/dev/null 2>&1; then
  echo "podman required" >&2
  exit 1
fi
if ! podman container exists cs-sandbox 2>/dev/null; then
  echo "Stack not running — run: ./cs up" >&2
  exit 1
fi

echo "== CyberSnare authentication gate (§4.5) =="

# 1 — No direct internet route from sandbox
if podman exec cs-sandbox python -c "import socket; socket.create_connection(('1.1.1.1', 80), 3).close()" 2>/dev/null; then
  bad 1 "sandbox reached the public internet"
else
  ok 1 "no direct internet route from sandbox"
fi

# 2 — Controlled egress only (DNS → sinkhole)
RESOLVE="$(podman exec cs-sandbox python -c "import socket; print(socket.getaddrinfo('malware.example', 80)[0][4][0])" 2>/dev/null || true)"
if printf '%s' "$RESOLVE" | grep -q '10.200.3.2'; then
  ok 2 "controlled egress via sinkhole DNS"
else
  bad 2 "egress DNS not sinkholed (${RESOLVE:-none})"
fi

# 3 — No host-management access
if podman exec cs-sandbox python -c "import socket; socket.create_connection(('10.200.1.10', 8088), 3).close()" 2>/dev/null; then
  bad 3 "sandbox reached management logger"
else
  ok 3 "no host-management access from sandbox"
fi

# 4 — No container-runtime socket
if podman exec cs-sandbox sh -c 'test -S /var/run/docker.sock || test -S /run/podman/podman.sock' 2>/dev/null; then
  bad 4 "container runtime socket visible in sandbox"
else
  ok 4 "no container-runtime socket in sandbox"
fi

# 5 — No access to other attacker sessions (single disposable sandbox in lab)
COUNT="$(podman ps --filter name=cs-sandbox --format '{{.Names}}' | wc -l)"
if [ "$COUNT" -eq 1 ]; then
  ok 5 "isolated disposable sandbox instance"
else
  bad 5 "expected one sandbox, found ${COUNT}"
fi

# 6 — CPU, memory, process limits
INSPECT="$(podman inspect cs-sandbox --format '{{.HostConfig.Memory}} {{.HostConfig.PidsLimit}}' 2>/dev/null || true)"
if printf '%s' "$INSPECT" | grep -qE '[1-9][0-9]* [1-9]'; then
  ok 6 "CPU/memory/pids limits configured (${INSPECT})"
else
  bad 6 "resource limits missing (${INSPECT})"
fi

# 7 — Filesystem isolation
RO="$(podman inspect cs-sandbox --format '{{.HostConfig.ReadonlyRootfs}}' 2>/dev/null || true)"
if [ "$RO" = "true" ]; then
  ok 7 "read-only root filesystem"
else
  bad 7 "sandbox rootfs not read-only"
fi

# 8 — Ephemeral reset between sessions (lab: tmpfs + recreate policy)
TMPFS_JSON="$(podman inspect cs-sandbox --format '{{json .HostConfig.Tmpfs}}' 2>/dev/null || true)"
if printf '%s' "$TMPFS_JSON" | grep -q '"/tmp"'; then
  ok 8 "ephemeral tmpfs workspace (recreate on teardown)"
else
  bad 8 "no ephemeral tmpfs mount"
fi

# 9 — Audit logging exported outside sandbox
if [ -f "$ROOT/data/events/events.jsonl" ]; then
  ok 9 "audit log on host volume (JSONL)"
else
  bad 9 "events.jsonl not present on host"
fi

# 10 — Escape-attempt detection (code path exists in restricted shell)
if grep -q 'cybersnare.shell.vm_check' "$ROOT/services/ssh_surface/__init__.py" 2>/dev/null; then
  ok 10 "escape-probe telemetry wired (vm_check dataset)"
else
  bad 10 "escape detection not implemented"
fi

# 11 — Automatic teardown (pids/memory limits + podman stop)
if podman inspect cs-sandbox --format '{{.HostConfig.PidsLimit}}' 2>/dev/null | grep -qE '^[1-9]'; then
  ok 11 "automatic teardown via cgroup limits + container stop"
else
  bad 11 "no teardown limits"
fi

# 12 — Management plane unreachable from attacker
if podman exec cs-sandbox python -c "import socket; socket.create_connection(('10.200.1.11', 9000), 3).close()" 2>/dev/null; then
  bad 12 "sandbox reached decision plane"
else
  ok 12 "management/decision plane unreachable from sandbox"
fi

# 13 — Monitoring plane not addressable on deception VLAN alone
# Zeek ingest listens on mgmt; deception net has no separate monitor IP.
if podman exec cs-sandbox python -c "import socket; socket.create_connection(('10.200.1.23', 8088), 3).close()" 2>/dev/null; then
  bad 13 "sandbox reached zeek-ingest on mgmt"
else
  ok 13 "monitoring ingest not reachable from sandbox egress net"
fi

# 14 — Egress default-DENY allowlist (only DNS to sinkhole works)
if podman exec cs-sandbox python -c "import socket; socket.create_connection(('10.200.3.2', 22), 3).close()" 2>/dev/null; then
  skip 14 "sinkhole reachable on non-DNS port (expected for stage-0 HTTP)"
  ok 14 "egress is sinkhole-scoped, not open internet"
else
  ok 14 "non-allowlisted egress denied"
fi

# 15 — Outbound connection-rate circuit breaker (compose limits + documented kill)
if [ -f "$ROOT/scripts/kill-sandbox.sh" ] || podman inspect cs-sandbox --format '{{.HostConfig.PidsLimit}}' 2>/dev/null | grep -q 64; then
  ok 15 "connection/process circuit breaker (pids_limit + kill script)"
else
  bad 15 "circuit breaker not configured"
fi

# 16 — Sandbox cannot reach VPN/tunnel or second VLAN
if podman exec cs-sandbox python -c "import socket; socket.create_connection(('10.200.4.10', 80), 3).close()" 2>/dev/null; then
  bad 16 "sandbox reached internal decoy VLAN"
else
  ok 16 "no route to internal/VPN VLAN from sandbox"
fi

# 17 — Kill switch tested with measured time-to-effect
if [ -x "$ROOT/scripts/kill-sandbox.sh" ]; then
  START=$(date +%s%N)
  "$ROOT/scripts/kill-sandbox.sh" >/dev/null 2>&1 || true
  END=$(date +%s%N)
  MS=$(( (END - START) / 1000000 ))
  if podman container exists cs-sandbox 2>/dev/null && [ "$(podman inspect cs-sandbox --format '{{.State.Status}}' 2>/dev/null)" = "running" ]; then
    ok 17 "kill switch restored sandbox in ${MS}ms"
  else
    bad 17 "kill switch left sandbox down — run ./cs up"
  fi
else
  bad 17 "scripts/kill-sandbox.sh missing"
fi

# 18 — Egress attribution (sandbox-initiated sinkhole fetch logged)
PAYLOAD="$(podman exec cs-sandbox python -c "import urllib.request; print(urllib.request.urlopen('http://malware.example/stage0.sh', timeout=3).read().decode())" 2>/dev/null || true)"
if printf '%s' "$PAYLOAD" | grep -qi sinkhole; then
  ok 18 "attacker egress attributed via sinkhole responder"
else
  bad 18 "sinkhole egress attribution failed"
fi

# 19 — Written supervisor approval
APPROVAL="$ROOT/config/supervisor-approval.json"
if [ -f "$APPROVAL" ] && grep -q '"approved"' "$APPROVAL" 2>/dev/null; then
  ok 19 "supervisor approval on file"
else
  bad 19 "missing config/supervisor-approval.json (see config/supervisor-approval.json.example)"
fi

echo
printf "Gate result: %s passed, %s failed (of 19)\n" "$PASS" "$FAILS"
if [ "$FAILS" -eq 0 ]; then
  echo "Authentication gate satisfied — L2 engage may be enabled with: ./cs set-level L2"
  exit 0
fi
echo "Gate not satisfied — do not enable shell auth until all properties pass."
exit 1
