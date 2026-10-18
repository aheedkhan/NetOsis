"""Tiny client honeypots use to call the controller — never raises.

A controller outage must never crash an attacker's session; callers just
treat `wake_ctid()` returning False the same as "couldn't wake it, try the
direct connect anyway and let that fail normally."
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request


def controller_base_url() -> str:
    return os.environ.get("NETOSIS_CONTROLLER_URL", "http://192.168.40.31:8000").rstrip("/")


def wake_ctid(ctid: int, *, timeout: float = 30.0) -> bool:
    if ctid is None:
        return False
    url = f"{controller_base_url()}/v1/pivot/wake"
    payload = json.dumps({"ctid": ctid}).encode()
    req = urllib.request.Request(
        url, data=payload, method="POST",
        headers={"Content-Type": "application/json", "X-Netosis-Token": os.environ.get("NETOSIS_INGEST_TOKEN", "")},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode())
        return bool(data.get("ok"))
    except Exception as exc:  # controller down/unreachable/slow — never fatal
        print(f"  [pivot-wake-error] ctid={ctid}: {exc}")
        return False
