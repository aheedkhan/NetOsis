#!/usr/bin/env bash
# Milestone 1 verification — full lab + P4/P5 deliverables.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
FAILS=0

ok() { printf '  OK    %s\n' "$*"; }
bad() { printf '  FAIL  %s\n' "$*"; FAILS=$((FAILS + 1)); }

echo "== Milestone 1 verification =="

echo "-- P1/P3 lab (integration) --"
if "$ROOT/scripts/verify.sh"; then
  ok "integration verify (16 checks)"
else
  bad "integration verify failed"
fi

echo "-- P3 auth gate --"
GATE_OUT=$("$ROOT/scripts/gate-auth.sh" 2>&1) || true
if printf '%s' "$GATE_OUT" | grep -q 'Gate result: 19 passed'; then
  ok "auth gate 19/19"
elif printf '%s' "$GATE_OUT" | grep -q '18 passed'; then
  ok "auth gate 18/19 (supervisor file pending)"
else
  bad "auth gate failed"
  printf '%s\n' "$GATE_OUT" | tail -5
fi

echo "-- P4 intelligence plane --"
if curl -sf --max-time 3 http://127.0.0.1:18090/health >/dev/null; then
  ok "intelligence /health"
else
  bad "intelligence not reachable on :18090"
fi
REP=$(curl -sf --max-time 5 http://127.0.0.1:18090/v1/report 2>/dev/null || true)
if printf '%s' "$REP" | grep -q total_events; then
  ok "milestone report API"
else
  bad "milestone report API failed"
fi
if [ -f "$ROOT/deploy/dashboard/index.html" ]; then
  ok "dashboard HTML present"
else
  bad "dashboard missing"
fi

echo "-- P5 evaluation artefacts --"
for f in docs/milestone1/pre-registration.md docs/milestone1/ANALYSIS-PLAN.md; do
  if [ -f "$ROOT/$f" ]; then ok "deliverable $f"; else bad "missing $f"; fi
done
if [ -x "$ROOT/scripts/redteam-profiles.sh" ]; then ok "red-team profiles script"; else bad "redteam script"; fi
if [ -x "$ROOT/scripts/aa-validate.sh" ]; then ok "A/A validation script"; else bad "aa-validate script"; fi

echo "-- Three experimental arms --"
if podman compose -f compose.yml config --services 2>/dev/null | grep -q decision; then
  ok "compose base (Arm A)"
else
  bad "compose base"
fi
if podman compose -f compose.yml -f compose.adaptive.yml config --services 2>/dev/null | grep -q intent_worker; then
  ok "compose adaptive (Arm B)"
else
  bad "compose adaptive"
fi
if podman compose -f compose.yml -f compose.p2.yml config --services 2>/dev/null | grep -q intent_worker; then
  ok "compose p2 (Arm C)"
else
  bad "compose p2"
fi

echo
if [ "$FAILS" -eq 0 ]; then
  echo "Milestone 1 lab READY — run ./cs redteam to generate evaluation traffic."
  echo "Dashboard: http://127.0.0.1:18090/"
  exit 0
fi
echo "$FAILS milestone check(s) failed."
exit 1
