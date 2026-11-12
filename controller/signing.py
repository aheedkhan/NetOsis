"""Signed node -> controller requests (HMAC-SHA256, per-node keys, replay-proof).

Why not just the shared token: a token travels in every request, so anyone who
can see the lab's traffic could replay or reuse it, and a node holding it could
pretend to be any other node. Here:

* The controller keeps one master secret (NETOSIS_INGEST_TOKEN in controller/.env).
* Each node gets its own key, derived from it:  key = HMAC(master, "netosis-node:" + name).
  `python3 scripts/node_keys.py <name>` prints it on the SOC VM. A node only
  ever sees its own key, never the master.
* Every request carries  X-Netosis-Node / X-Netosis-Ts / X-Netosis-Sig  where
  sig = HMAC(key, ts \\n METHOD \\n path \\n sha256(body)). The key never goes
  on the wire; a captured request is useless after SKEW seconds and can't be
  replayed inside that window (seen signatures are remembered).
* The controller then checks that the node only reports about itself.

agent/netosis_agent.py carries its own copy of `sign()` (it is installed as a
single standalone file); tests/unit/test_signing.py keeps the two identical.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import threading
import time
from typing import Mapping

H_NODE, H_TS, H_SIG = "X-Netosis-Node", "X-Netosis-Ts", "X-Netosis-Sig"
SKEW = 90  # seconds; CTs share the Proxmox host clock, the SOC VM runs NTP
NODE_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


def node_key(master: str, node: str) -> str:
    return hmac.new(master.encode(), b"netosis-node:" + node.encode(), hashlib.sha256).hexdigest()


def sign(key: str, ts: str, method: str, path: str, body: bytes) -> str:
    msg = f"{ts}\n{method.upper()}\n{path}\n{hashlib.sha256(body).hexdigest()}".encode()
    return hmac.new(key.encode(), msg, hashlib.sha256).hexdigest()


def credentials() -> tuple[str, str]:
    """(node key, legacy token) from this process's environment."""
    return os.environ.get("NETOSIS_NODE_KEY", "").strip(), os.environ.get("NETOSIS_INGEST_TOKEN", "")


def auth_headers(method: str, path: str, body: bytes, *, node: str | None = None,
                 creds: tuple[str, str] | None = None) -> dict[str, str]:
    """Headers for a request from this node: signed if it has a node key, else the legacy token."""
    key, token = creds or credentials()
    name = (node or os.environ.get("NETOSIS_NODE_NAME", "")).strip()
    if key and name:
        ts = str(int(time.time()))
        return {H_NODE: name, H_TS: ts, H_SIG: sign(key, ts, method, path, body)}
    return {"X-Netosis-Token": token}


class Verifier:
    """Checks signed requests against the master secret. Thread-safe."""

    def __init__(self, master: str, nodes: set[str] | None = None) -> None:
        self.master = master
        self.nodes = nodes  # None = any well-formed node name
        self._seen: dict[str, float] = {}
        self._lock = threading.Lock()

    def verify(self, headers: Mapping[str, str], method: str, path: str, body: bytes) -> str | None:
        """Return the authenticated node name, or None."""
        node, ts, sig = (headers.get(h, "") or "" for h in (H_NODE, H_TS, H_SIG))
        if not (self.master and node and ts and sig) or not NODE_RE.match(node) or not ts.isdigit():
            return None
        if self.nodes is not None and node not in self.nodes:
            return None
        now = time.time()
        if abs(now - int(ts)) > SKEW:
            return None
        expected = sign(node_key(self.master, node), ts, method, path, body)
        if not hmac.compare_digest(expected, sig.lower()):
            return None
        with self._lock:
            if sig in self._seen:
                return None  # replay
            if len(self._seen) > 50_000:
                self._seen = {s: t for s, t in self._seen.items() if t > now}
            self._seen[sig] = now + 2 * SKEW
        return node
