#!/usr/bin/env bash
# Self-signed certificates for the NexusCorp DMZ hosts.
#
# A corporate site that answers 443 with plaintext is the kind of detail a
# careful operator notices immediately, so the DMZ terminates real TLS. The
# certificates are internally consistent: one fictional issuing CA, matching
# subject names, plausible validity.
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

[ -f ca.key ] || {
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -keyout ca.key -out ca.crt \
    -subj "/C=NL/O=NexusCorp Industrial Systems/CN=NexusCorp Internal Issuing CA" 2>/dev/null
  echo "generated issuing CA"
}

gen() {
  host="$1"; cn="$2"
  [ -f "$host.crt" ] && return 0
  openssl req -newkey rsa:2048 -nodes -keyout "$host.key" -out "$host.csr" \
    -subj "/C=NL/ST=Zuid-Holland/L=Rotterdam/O=NexusCorp Industrial Systems/CN=$cn" 2>/dev/null
  openssl x509 -req -in "$host.csr" -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out "$host.crt" -days 825 -sha256 \
    -extfile <(printf "subjectAltName=DNS:%s\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n" "$cn") 2>/dev/null
  rm -f "$host.csr"
  echo "generated $host ($cn)"
}

gen www01 www.nexuscorp.example
gen mail01 mail.nexuscorp.example
gen vpn01 vpn.nexuscorp.example
chmod 644 ./*.key ./*.crt
