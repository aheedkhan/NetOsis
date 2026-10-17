#!/usr/bin/env bash
# Set up a REAL (non-honeypot) lab server inside its container/VM, as root.
#
#   curl -fsSL https://raw.githubusercontent.com/aheedkhan/NetOsis/main/scripts/real-server-setup.sh | bash -s web
#
# Roles:
#   web  ENT-WEB-REAL-01     192.168.30.40  nginx corporate site on :80 (published on WAN :80)
#   db   FINANCE-DB-REAL-01  192.168.10.50  PostgreSQL :5432 with a small finance schema
#   app  OPS-APP-REAL-01     192.168.20.50  nginx "ERP portal" on :8080
#
# These are the assets the honeypots must NEVER reach (Proxmox FW + OPNsense);
# no NetOsis code runs here.
set -euo pipefail

ROLE="${1:-}"
[[ "$(id -u)" -eq 0 ]] || { echo "[!] run as root" >&2; exit 1; }
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq

case "$ROLE" in
web)
  apt-get install -y -qq nginx >/dev/null
  cat >/var/www/html/index.html <<'EOF'
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>NetOsis Corp</title>
<style>body{font-family:Arial,sans-serif;margin:0;background:#f4f6f8;color:#1d2733}
header{background:#12324a;color:#fff;padding:18px 40px}main{padding:40px;max-width:820px}
a{color:#12324a}footer{padding:20px 40px;color:#6b7785;font-size:13px}</style></head>
<body><header><h1>NetOsis Corp</h1>Logistics &amp; Operations Services</header>
<main><h2>Welcome</h2>
<p>NetOsis Corp provides finance, operations and supply-chain services to regional partners.</p>
<p>Employees: use the internal portal from the corporate network or VPN.</p>
<p>Contact: <a href="mailto:it-helpdesk@netosis.internal">it-helpdesk@netosis.internal</a></p></main>
<footer>&copy; 2026 NetOsis Corp &middot; ent-web-01.corp</footer></body></html>
EOF
  sed -i 's/# server_tokens off;/server_tokens off;/' /etc/nginx/nginx.conf || true
  systemctl enable --now nginx >/dev/null
  systemctl reload nginx
  curl -fsS -o /dev/null -w "[+] nginx :80 -> HTTP %{http_code}\n" http://127.0.0.1/
  ;;
db)
  apt-get install -y -qq postgresql >/dev/null
  systemctl enable --now postgresql >/dev/null
  su - postgres -c "psql -v ON_ERROR_STOP=1" <<'EOF'
SELECT 'CREATE DATABASE finance' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname='finance')\gexec
\c finance
CREATE TABLE IF NOT EXISTS vendors (id serial PRIMARY KEY, name text, iban text, contact text);
CREATE TABLE IF NOT EXISTS invoices (id serial PRIMARY KEY, vendor_id int REFERENCES vendors(id),
  amount numeric(12,2), due date, status text);
INSERT INTO vendors (name, iban, contact)
  SELECT * FROM (VALUES
    ('Harbor Freight Partners','PK36SCBL0000001123456702','ap@harborfp.example'),
    ('Delta Office Supply','PK24MEZN0001090102345678','billing@deltaoffice.example'),
    ('Northline Transport','PK71HABB0002345678901234','accounts@northline.example')) v
  WHERE NOT EXISTS (SELECT 1 FROM vendors);
INSERT INTO invoices (vendor_id, amount, due, status)
  SELECT * FROM (VALUES (1, 48250.00, DATE '2026-11-01', 'open'),
                        (2, 1320.50, DATE '2026-10-20', 'paid'),
                        (3, 97110.75, DATE '2026-11-15', 'open')) v
  WHERE NOT EXISTS (SELECT 1 FROM invoices);
EOF
  # Listen on the LAN so the real app server can connect; FW decides who may.
  CONF_DIR="$(ls -d /etc/postgresql/*/main | head -1)"
  sed -i "s/^#\?listen_addresses.*/listen_addresses = '*'/" "$CONF_DIR/postgresql.conf"
  grep -q "192.168.20.50/32" "$CONF_DIR/pg_hba.conf" || \
    echo "host finance all 192.168.20.50/32 scram-sha-256" >>"$CONF_DIR/pg_hba.conf"
  systemctl restart postgresql
  su - postgres -c "psql -d finance -Atc 'select count(*) from invoices'" | sed 's/^/[+] invoices rows: /'
  ;;
app)
  apt-get install -y -qq nginx >/dev/null
  mkdir -p /var/www/erp
  cat >/var/www/erp/index.html <<'EOF'
<!doctype html><html><head><meta charset="utf-8"><title>NetOsis ERP</title></head>
<body style="font-family:Arial;background:#eef1f4"><div style="max-width:360px;margin:80px auto;
background:#fff;padding:30px;border-radius:6px"><h2>NetOsis ERP &middot; Operations</h2>
<form><p><input placeholder="Username" style="width:100%"></p>
<p><input type="password" placeholder="Password" style="width:100%"></p>
<p><button type="button">Sign in</button></p></form>
<small>ops-app-01.corp &middot; authorised staff only</small></div></body></html>
EOF
  cat >/etc/nginx/sites-available/erp <<'EOF'
server { listen 8080; root /var/www/erp; index index.html; server_tokens off; }
EOF
  ln -sf /etc/nginx/sites-available/erp /etc/nginx/sites-enabled/erp
  systemctl enable --now nginx >/dev/null
  systemctl reload nginx
  curl -fsS -o /dev/null -w "[+] ERP :8080 -> HTTP %{http_code}\n" http://127.0.0.1:8080/
  ;;
*)
  echo "Usage: $0 <web|db|app>" >&2
  exit 1
  ;;
esac
