#!/usr/bin/env bash
# Bring up the adaptive lab and an automated attacker OUTSIDE the perimeter.
#
# The attacker is attached only to the simulated Internet segment
# (203.0.113.0/24) and reaches the deception surface exclusively through the
# published address dev.nexuscorp.example (203.0.113.20), DNAT'd by cs-edge-fw
# to the sensor inside the deception zone. Everything it does — the port sweep,
# the credential attempts — has to cross both firewalls to land, which is what
# makes the resulting telemetry mean something.
#
# This profile is deliberately automated (fast, wide, no think time), so
# lib/cs/operator.py should classify it as `automated` and the decision plane
# should drop it at cs-edge-fw within a few requests. See scripts/operator-up.sh
# for the human-paced counterpart, which is expected to be engaged instead.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

COMPOSE="podman compose"
FILES="-f compose.yml -f compose.adaptive.yml -f compose.attacker.yml"

echo "== Bring up the NexusCorp org lab (P1 adaptive) + attacker =="
mkdir -p data/events data/manifests data/zeek
rm -f data/manifests/.pinned

$COMPOSE $FILES up -d --build

echo "== Wait for the deception surface to be ready =="
# Polled from cs-sensor itself, against its own local listener — never from the
# attacker container. A readiness probe fired repeatedly from the tracked
# identity, on a fixed interval, with curl's bare default user-agent, is
# exactly what lib/cs/operator.py is built to catch: it is machine-shaped
# traffic, and it would poison this actor's belief state with automation
# evidence before the actual demo traffic ever runs — the orchestration script
# would end up as part of the experiment it is only meant to set up. The same
# separation that keeps the sensor from capturing its own management-plane
# polling applies here.
for i in $(seq 1 40); do
  if podman exec cs-sensor bash -c 'exec 3<>/dev/tcp/127.0.0.1/8443' 2>/dev/null; then
    break
  fi
  sleep 2
done

echo "== Automated recon from outside (nc sweep + curl, no nmap: setuid is blocked in the container) =="
podman exec cs-attacker sh -c '
  for ip in 203.0.113.20 203.0.113.10; do
    for p in 21 22 23 25 53 80 110 135 139 143 443 445 993 1433 3306 3389 5432 5900 8080 8443 9200 27017; do
      timeout 0.2 nc -z -w 1 "$ip" "$p" 2>/dev/null
    done
  done
' || true

echo "== Credential attempts (SSH + the web login endpoint) =="
podman exec cs-attacker sh -c '
  for u in root admin oracle postgres test ubuntu deploy git; do
    timeout 3 ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=3 -o BatchMode=yes "$u@203.0.113.20" true 2>/dev/null
  done
  for i in 1 2 3 4 5; do
    curl -sk -m 2 -o /dev/null -X POST -d "username=admin&password=p$i" https://203.0.113.20/login 2>/dev/null
  done
' || true

sleep 6
echo
echo "== Verdict =="
podman logs cs-decision 2>&1 | grep -E "BLOCK 203\.0\.113\.66" | tail -3 || echo "  not yet blocked — give it a few more seconds and check: ./cs blocked"
echo
echo "  SIEM:      http://127.0.0.1:18090/"
echo "  Monitor:   ./cs monitor"
echo "  Blocklist: ./cs blocked"
echo
echo "  Manual poking, from inside the attacker container:"
echo "    ./cs attacker-shell"
echo "    curl -vk https://203.0.113.20/          # www.nexuscorp.example: https://203.0.113.10/"
echo "    ssh -p 22 guest@203.0.113.20             # should now be refused if BLOCKed"
