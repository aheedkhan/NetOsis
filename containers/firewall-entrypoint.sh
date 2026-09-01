#!/bin/sh
# Zone firewall entrypoint.
#
# Podman does not guarantee which network lands on which ethN, so every
# interface is resolved by the address the compose file pinned to it. The
# ruleset templates refer to interfaces as @IF_<ZONE>@ and are substituted here.
set -eu

ROLE="${CS_FW_ROLE:?CS_FW_ROLE must be edge or core}"
RULES="${CS_FW_RULES:-/etc/cs/${ROLE}.nft}"

log() { echo "[fw:${ROLE}] $*" >&2; }

# ---- interface discovery -------------------------------------------------
# CS_FW_IFMAP="INET=203.0.113.2 DMZ=172.31.10.2 TRANSIT=172.31.99.2"
ifname_for() {
  addr="$1"
  ip -o -4 addr show | awk -v a="$addr" '$4 ~ "^"a"/" { print $2; exit }'
}

wait_for_addr() {
  addr="$1"; tries=0
  while [ "$tries" -lt 50 ]; do
    name="$(ifname_for "$addr")"
    [ -n "$name" ] && { echo "$name"; return 0; }
    tries=$((tries + 1))
    sleep 0.2
  done
  return 1
}

SED_ARGS=""
for pair in ${CS_FW_IFMAP:-}; do
  zone="${pair%%=*}"
  addr="${pair#*=}"
  name="$(wait_for_addr "$addr")" || {
    log "FATAL: no interface holds $addr (zone $zone)"
    ip -o -4 addr show >&2
    exit 1
  }
  log "zone $zone -> $name ($addr)"
  SED_ARGS="$SED_ARGS -e s|@IF_${zone}@|${name}|g"
done

# ---- forwarding ----------------------------------------------------------
# The runtime sets this from the compose `sysctls:` block at creation time,
# because /proc/sys is mounted read-only here. Try anyway for the case where
# the container is run without that block, then verify rather than assume.
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
if [ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0)" != "1" ]; then
  log "FATAL: ip_forward is off and cannot be set from inside the container."
  log "       Add 'sysctls: {net.ipv4.ip_forward: \"1\"}' to this service."
  exit 1
fi

# Conntrack must see the reply direction even when the route is asymmetric.
sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null 2>&1 || true

# ---- virtual IPs (the public address block the edge answers for) ---------
# CS_FW_VIPS="203.0.113.10/24@203.0.113.2 203.0.113.11/24@203.0.113.2"
for spec in ${CS_FW_VIPS:-}; do
  vip="${spec%%@*}"
  onaddr="${spec#*@}"
  dev="$(ifname_for "$onaddr")"
  if [ -n "$dev" ]; then
    ip addr add "$vip" dev "$dev" 2>/dev/null && log "vip $vip on $dev" || true
  else
    log "WARNING: no device for vip $vip (anchor $onaddr)"
  fi
done

# ---- routes to zones behind the other firewall ---------------------------
# CS_FW_ROUTES="10.10.20.0/24:172.31.99.3 10.10.30.0/24:172.31.99.3"
for spec in ${CS_FW_ROUTES:-}; do
  net="${spec%%:*}"
  gw="${spec#*:}"
  ip route replace "$net" via "$gw" && log "route $net via $gw"
done

# ---- ruleset -------------------------------------------------------------
[ -f "$RULES" ] || { log "FATAL: ruleset $RULES not found"; exit 1; }
# shellcheck disable=SC2086
sed $SED_ARGS "$RULES" > /run/ruleset.nft
nft -f /run/ruleset.nft || { log "FATAL: ruleset rejected"; cat -n /run/ruleset.nft >&2; exit 1; }
log "ruleset loaded ($(nft list ruleset | wc -l) lines)"

# ---- telemetry agent -----------------------------------------------------
exec python3 -m services.fw_agent
