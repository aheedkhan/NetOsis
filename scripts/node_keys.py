#!/usr/bin/env python3
"""Print per-node signing keys (run on the SOC VM, as root, inside /opt/netosis).

    python3 scripts/node_keys.py                      # the three honeypots
    python3 scripts/node_keys.py ent-web-01           # one node
    python3 scripts/node_keys.py --env > /root/netosis-node-keys.env

Each key is derived from the master secret in controller/.env and only lets
that one node report about itself. Give each CT only its own key.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from controller.signing import NODE_RE, node_key  # noqa: E402

DEFAULT_NODES = ["ent-web-01", "finance-db-01", "ops-app-01"]


def master() -> str:
    val = os.environ.get("NETOSIS_INGEST_TOKEN", "")
    env = ROOT / "controller" / ".env"
    if not val and env.is_file():
        for line in env.read_text(encoding="utf-8").splitlines():
            if line.startswith("NETOSIS_INGEST_TOKEN="):
                val = line.split("=", 1)[1].strip().strip("'\"")
    return val


def main(argv: list[str]) -> int:
    as_env = "--env" in argv
    nodes = [a for a in argv if not a.startswith("--")] or DEFAULT_NODES
    secret = master()
    if not secret:
        print("[!] no NETOSIS_INGEST_TOKEN in controller/.env (run scripts/soc-dashboard-setup.sh first)", file=sys.stderr)
        return 1
    for n in nodes:
        if not NODE_RE.match(n):
            print(f"[!] bad node name: {n}", file=sys.stderr)
            return 1
        key = node_key(secret, n)
        print(f"{n}={key}" if as_env else f"{n:<16} {key}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
