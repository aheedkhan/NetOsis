#!/usr/bin/env bash
# Bring up the adaptive lab and a hand-paced operator OUTSIDE the perimeter.
#
# Same network position as scripts/attacker-up.sh — the operator container sits
# on the simulated Internet segment only and reaches the deception surface
# through the same published address. The only thing that differs from the
# attacker profile is behaviour: scripts/human-session.sh looks at one thing at
# a time, pauses to read responses, and mistypes a command before correcting
# it. lib/cs/operator.py should classify this as `interactive_operator` and the
# decision plane should escalate it into L2 (restricted shell) rather than
# dropping it.
#
# Run both profiles side by side to see the discrimination directly:
#   ./cs attacker   &
#   ./cs operator   &
#   wait
#   ./cs blocked          # the attacker's address
#   ./cs monitor           # the operator's level climbing
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

COMPOSE="podman compose"
FILES="-f compose.yml -f compose.adaptive.yml -f compose.attacker.yml"

echo "== Bring up the NexusCorp org lab (P1 adaptive) + operator =="
mkdir -p data/events data/manifests data/zeek
rm -f data/manifests/.pinned

$COMPOSE $FILES up -d --build operator decision logger gnn_scorer intelligence \
  sensor ssh http zeek_ingest sinkhole sandbox edge-fw core-fw \
  www01 mail01 vpn01 dc01 fs01 erp01 wks01 db01 bkp01

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

echo "== Running the hand-paced session (takes a few minutes — it is deliberately slow) =="
podman exec cs-operator bash /opt/cs/human-session.sh

echo
echo "== Verdict =="
podman exec cs-decision python -c "
import urllib.request, json
d = json.loads(urllib.request.urlopen('http://127.0.0.1:9000/v1/belief', timeout=4).read())['actors']
rec = d.get('ip:203.0.113.77')
if rec:
    print(f\"  level={rec.get('level')}  capability={rec.get('capability')}  p_human={rec.get('p_human'):.3f}\")
else:
    print('  no record yet for ip:203.0.113.77 — check ./cs monitor')
" 2>/dev/null || true
echo
echo "  SIEM:    http://127.0.0.1:18090/"
echo "  Monitor: ./cs monitor"
echo
echo "  Manual poking, from inside the operator container:"
echo "    ./cs operator-shell"
echo "    ssh -p 22 guest@203.0.113.20             # nexus2024 — should be open once escalated"
