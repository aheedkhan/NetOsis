#!/bin/sh
set -e
mkdir -p /zeek/logs
cd /zeek/logs

# Return routes.
#
# The perimeter firewall deliberately does not source-NAT into the deception
# zone: actor identity is keyed on the observed source address, so the
# adversary's real address has to survive the whole path. The cost of that
# choice is that this host must be told how to answer a network that is not
# on-link. CS_RETURN_ROUTES is "cidr:gateway" pairs.
for spec in ${CS_RETURN_ROUTES:-}; do
  net="${spec%%:*}"
  gw="${spec#*:}"
  if ip route replace "$net" via "$gw" 2>/dev/null; then
    echo "return route $net via $gw" >&2
  else
    echo "WARNING: could not install return route $net via $gw" >&2
  fi
done

# Capture filter.
#
# The sensor is dual-homed: the deception bridge it is meant to watch, and the
# management bridge it uses to reach the logger. Capturing "any" therefore also
# records the control plane talking to itself, which is not adversary evidence
# and actively harms the system — a polling loop is the most metronomic traffic
# on the network, so the operator classifier will conclude that the management
# plane is a scanner. Excluding the management range here is what keeps the
# sensor from observing its own infrastructure.
#
# ARP and IPv6 link-local are excluded as well. Podman's bridges generate a
# constant background of router solicitation and neighbour discovery, and every
# one of those produced a phantom actor keyed on an fe80:: address with a
# belief state of its own. The lab's surfaces bind IPv4 only, so no adversary
# evidence is lost by dropping IPv6 here.
# The exclusion is subtler than "drop the whole management subnet". Rootless
# podman's slirp4netns forwards a published host port (127.0.0.1:8443 on the
# host) onto the CONTAINER'S OWN address on its loopback path, not onto
# 127.0.0.1 inside the container — so a connection from the outside to the
# published SSH/HTTPS ports shows up here as this sensor's own management
# address talking to itself (10.200.1.20 -> 10.200.1.20). A blanket "not net
# 10.200.1.0/24" excludes that self-loop along with the genuine cross-host
# noise it was meant to remove, which blackholed every piece of adversary
# telemetry reached through a published port. So: drop the management subnet
# EXCEPT the sensor's own address talking only to itself.
# Parenthesised explicitly: BPF's "and" binds tighter than "or", so without
# the outer group the trailing "and not arp and not ip6" attaches only to the
# loopback clause and ARP/IPv6 noise leaks back in everywhere outside the
# management subnet — caught by testing this against a live capture, not by
# reading it.
# 10.200.9.0/24 is the llm bridge — ssh-surface (sharing this netns) uses it
# to reach the host's Ollama instance for the dynamic shell fallback, and
# that call would otherwise be captured as if it were adversary traffic,
# same class of bug as the earlier management-plane self-surveillance fix.
CS_CAPTURE_FILTER="${CS_CAPTURE_FILTER:-(not net 10.200.1.0/24 or (src host 10.200.1.20 and dst host 10.200.1.20)) and not net 10.200.9.0/24 and not arp and not ip6}"
echo "zeek capturing any, filter: ${CS_CAPTURE_FILTER}" >&2
# Rootless published ports land on lo, not the deception veth.
exec tcpdump -i any -U -s 0 -w - ${CS_CAPTURE_FILTER} 2>/dev/null \
  | zeek -C -r - /site/local.zeek
