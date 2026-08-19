#!/bin/sh
set -e
mkdir -p /zeek/logs
cd /zeek/logs
echo "zeek capturing any (tcpdump pipe)" >&2
# Rootless published ports land on lo, not the deception veth.
exec tcpdump -i any -U -s 0 -w - 2>/dev/null | zeek -C -r - /site/local.zeek
