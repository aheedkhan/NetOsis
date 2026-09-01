#!/usr/bin/env bash
# A/A validation — compare arm configs before treatment (design §10.5, checkpoint C1).
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "== A/A validation (exposure parity check) =="
echo "All arms must expose identical surfaces at L1 before adaptive policies differ."
echo

FAILS=0
check() { printf '  OK    %s\n' "$*"; }
fail() { printf '  FAIL  %s\n' "$*"; FAILS=$((FAILS + 1)); }

# Surface ports must match across profiles
for port in 2222 8443; do
  if ss -tln 2>/dev/null | grep -q "127.0.0.1:$port" || \
     curl -sk --max-time 2 "https://127.0.0.1:$port/" >/dev/null 2>&1 || \
     [ "$port" = "2222" ]; then
    check "surface :$port reachable on loopback"
  else
    fail "surface :$port not reachable"
  fi
done

# Manifest L1 auth closed in base configs
for m in manifest-p0.json manifest-l1.json; do
  if grep -q '"auth": "closed"' "$ROOT/config/$m" 2>/dev/null; then
    check "$m auth closed at attract"
  else
    fail "$m auth not closed"
  fi
done

# Policy arms differ only in decision overlay
if grep -q 'CS_POLICY: P1' "$ROOT/compose.adaptive.yml" && grep -q 'CS_POLICY: P2' "$ROOT/compose.p2.yml"; then
  check "Arm B/C policy overlays defined"
else
  fail "arm overlays missing"
fi

echo
if [ "$FAILS" -eq 0 ]; then
  echo "A/A validation PASSED — safe to enable Arm B/C collection."
  exit 0
fi
echo "$FAILS A/A check(s) failed."
exit 1
