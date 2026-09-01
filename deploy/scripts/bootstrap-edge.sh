#!/usr/bin/env bash
# Bootstrap cs-edge — Ubuntu 24.04 DMZ: real web + firewall + WireGuard to lab.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

echo "== CyberSnare edge bootstrap =="

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root: sudo $0" >&2
  exit 1
fi

apt-get update
apt-get install -y nginx nftables wireguard openssl

# Real public site
mkdir -p /var/www/nexuscorp /etc/nginx/ssl
if [ ! -f /etc/nginx/ssl/nexuscorp.crt ]; then
  openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/nginx/ssl/nexuscorp.key \
    -out /etc/nginx/ssl/nexuscorp.crt \
    -subj "/CN=nexuscorp.example/O=NexusCorp"
fi
cp "$ROOT/deploy/org/edge/nginx-default.conf" /etc/nginx/sites-available/nexuscorp
ln -sf /etc/nginx/sites-available/nexuscorp /etc/nginx/sites-enabled/nexuscorp
rm -f /etc/nginx/sites-enabled/default
echo '<h1>NexusCorp</h1><p>Enterprise solutions.</p>' > /var/www/nexuscorp/index.html
systemctl enable --now nginx

cp "$ROOT/deploy/org/firewall/nftables-edge.conf" /etc/nftables.conf
systemctl enable --now nftables

echo
echo "Edge bootstrap complete."
echo "Next steps:"
echo "  1. Copy deploy/org/edge/wireguard-lab.conf.example → /etc/wireguard/wg0.conf"
echo "  2. Fill in keys and lab public IP"
echo "  3. systemctl enable --now wg-quick@wg0"
echo "Real site: https://$(hostname -I | awk '{print $1}')/"
echo "Deception ports 2222/8080/8443 DNAT to lab via wg0."
