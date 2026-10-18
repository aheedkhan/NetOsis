"""The lab as the SOC sees it: gateway, VLANs, honeypots, production, SOC.

Static facts only (from ops/SERVER_RUNBOOK.md and config/network/vlans.yml).
Live state (is a honeypot powered on? how many sessions?) is merged in by
SocStore.network() from sensor heartbeats.
"""

from __future__ import annotations

from typing import Any

# kind: honeypot (sensor, reports telemetry) | production (real asset, must stay untouched)
#       | decoy (answered by theater only) | gateway
VLANS: list[dict[str, Any]] = [
    {
        "id": 30, "name": "Enterprise", "cidr": "192.168.30.0/24", "gateway": "192.168.30.254",
        "hosts": [
            {"name": "ent-web-01", "ip": "192.168.30.10", "kind": "honeypot", "ctid": 102, "note": "WAN-facing entry point"},
            {"name": "ent-web-real-01", "ip": "192.168.30.40", "kind": "production", "note": "corporate site"},
            {"name": "ent-dc-01", "ip": "192.168.30.21", "kind": "decoy", "note": "domain controller (theater)"},
            {"name": "ent-mail-01", "ip": "192.168.30.25", "kind": "decoy", "note": "mail (theater)"},
        ],
    },
    {
        "id": 10, "name": "Finance", "cidr": "192.168.10.0/24", "gateway": "192.168.10.254",
        "hosts": [
            {"name": "finance-db-01", "ip": "192.168.10.10", "kind": "honeypot", "ctid": 104, "note": "wakes on lateral movement"},
            {"name": "finance-db-real-01", "ip": "192.168.10.50", "kind": "production", "note": "finance database"},
            {"name": "finance-app-01", "ip": "192.168.10.20", "kind": "decoy", "note": "portal (theater)"},
        ],
    },
    {
        "id": 20, "name": "Operations", "cidr": "192.168.20.0/24", "gateway": "192.168.20.254",
        "hosts": [
            {"name": "ops-app-01", "ip": "192.168.20.10", "kind": "honeypot", "ctid": 105, "note": "wakes on lateral movement"},
            {"name": "ops-app-real-01", "ip": "192.168.20.50", "kind": "production", "note": "ERP portal"},
            {"name": "ops-backup-01", "ip": "192.168.20.30", "kind": "decoy", "note": "backup (theater)"},
        ],
    },
    {
        "id": 40, "name": "SOC", "cidr": "192.168.40.0/24", "gateway": "192.168.40.254",
        "hosts": [
            {"name": "controller", "ip": "192.168.40.31", "kind": "soc", "note": "LLM, RAG, this dashboard"},
        ],
    },
]

EDGE = {"name": "OPNsense", "wan": "172.30.227.100", "note": "public IP for the lab"}
OUTSIDE = {"name": "Outside", "note": "attackers arrive here"}
