"""
Kubernetes-native firewall agent.

The compose deployment blocks a source address by adding it to an nftables
set inside a firewall container (services/fw_agent). There is no equivalent
container in the Kubernetes deployment — segmentation there is enforced by
Cilium reading CiliumNetworkPolicy objects, not by a packet-filtering process
this service could reach into directly. So blocking here means something
different but achieves the same effect: maintain one
CiliumClusterwideNetworkPolicy naming every currently-blocked address in an
`ingressDeny` rule, and apply it through the Kubernetes API.

Cilium evaluates deny rules before allow rules regardless of which policy
object they came from, so a blocked address is refused even though the
namespace's own allow policies (deploy/k8s/generated/policies.yaml) still say
yes — the same precedence relationship the nftables ruleset has between its
`blocked` set and its ordinary accept rules.

This process needs a ServiceAccount bound to a ClusterRole permitting it to
get/create/update CiliumClusterwideNetworkPolicy objects — see
deploy/k8s/base/fw-agent.yaml for the RBAC. `kubectl` is shelled out to rather
than pulling in the Kubernetes Python client, matching the rest of this
codebase's preference for auditable subprocess calls over an SDK dependency
that would only be used here.
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import time
from typing import Any

from cs.tinyhttp import json_body, serve

BIND = os.environ.get("CS_BIND", "0.0.0.0")
PORT = int(os.environ.get("CS_PORT", "9400"))
STATE_PATH = os.environ.get("CS_FW_STATE", "/data/blocked.json")
POLICY_NAME = os.environ.get("CS_FW_POLICY_NAME", "cs-blocklist")
SWEEP_INTERVAL_S = float(os.environ.get("CS_FW_SWEEP_INTERVAL", "10"))

# ip -> expires_at (unix time)
_blocked: dict[str, float] = {}
_stats = {"blocks": 0, "unblocks": 0, "sweeps": 0, "apply_errors": 0}
_lock = asyncio.Lock()


def _load_state() -> None:
    global _blocked
    try:
        with open(STATE_PATH, encoding="utf-8") as fh:
            _blocked = {k: float(v) for k, v in json.load(fh).items()}
    except (FileNotFoundError, json.JSONDecodeError, ValueError):
        _blocked = {}


def _save_state() -> None:
    os.makedirs(os.path.dirname(STATE_PATH) or ".", exist_ok=True)
    tmp = STATE_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(_blocked, fh)
    os.replace(tmp, STATE_PATH)


def _policy_yaml() -> str:
    """
    One CiliumClusterwideNetworkPolicy covering every currently-blocked
    address. Rebuilt in full on every change rather than patched incrementally
    — with at most a few dozen blocked addresses at once, a full replace is
    simpler to reason about and cannot drift from `_blocked`.
    """
    if not _blocked:
        # An empty ingressDeny fromCIDR list is invalid, so with nothing
        # blocked the policy is applied with a rule that can never match
        # instead of being deleted — deleting and recreating on every single
        # block/unblock cycle would race with Cilium's own reconciliation.
        cidrs = ["0.0.0.0/32"]
    else:
        cidrs = [f"{ip}/32" for ip in sorted(_blocked)]
    cidr_lines = "\n".join(f"            - \"{c}\"" for c in cidrs)
    return f"""apiVersion: cilium.io/v2
kind: CiliumClusterwideNetworkPolicy
metadata:
  name: {POLICY_NAME}
  labels:
    cybersnare.io/managed-by: k8s_fw_agent
spec:
  description: "Automated actors dropped by the decision plane's capability gate — see lib/cs/operator.py"
  endpointSelector: {{}}
  ingressDeny:
    - fromCIDR:
{cidr_lines}
"""


def _kubectl_apply(yaml_text: str) -> tuple[bool, str]:
    proc = subprocess.run(
        ["kubectl", "apply", "-f", "-"],
        input=yaml_text,
        capture_output=True,
        text=True,
        timeout=10,
    )
    return proc.returncode == 0, (proc.stderr or proc.stdout or "").strip()


async def _apply_locked() -> tuple[bool, str]:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _kubectl_apply, _policy_yaml())


async def block(ip: str, ttl_s: int) -> tuple[bool, str]:
    async with _lock:
        _blocked[ip] = time.time() + ttl_s
        ok, err = await _apply_locked()
        if ok:
            _save_state()
            _stats["blocks"] += 1
        else:
            _stats["apply_errors"] += 1
        return ok, err


async def unblock(ip: str) -> tuple[bool, str]:
    async with _lock:
        _blocked.pop(ip, None)
        ok, err = await _apply_locked()
        if ok:
            _save_state()
            _stats["unblocks"] += 1
        else:
            _stats["apply_errors"] += 1
        return ok, err


async def sweeper() -> None:
    """Expire blocks whose TTL has passed, same contract as the nftables `timeout` flag."""
    while True:
        await asyncio.sleep(SWEEP_INTERVAL_S)
        now = time.time()
        expired = [ip for ip, exp in _blocked.items() if exp <= now]
        if not expired:
            continue
        async with _lock:
            for ip in expired:
                _blocked.pop(ip, None)
            ok, err = await _apply_locked()
            if ok:
                _save_state()
                _stats["sweeps"] += 1
                print(f"fw_agent(k8s): expired {expired}", flush=True)
            else:
                _stats["apply_errors"] += 1
                print(f"fw_agent(k8s): failed to apply after expiry: {err}", flush=True)


async def handler(req: dict) -> tuple[int, dict[str, str], bytes]:
    if req["method"] == "GET" and req["path"] == "/health":
        body = json.dumps({"ok": True, "backend": "cilium", **_stats, "blocked_count": len(_blocked)}).encode()
        return 200, {"Content-Type": "application/json"}, body

    if req["method"] == "GET" and req["path"] == "/v1/blocked":
        now = time.time()
        rows = [
            {"ip": ip, "expires_s": round(exp - now), "packets_dropped": None}
            for ip, exp in sorted(_blocked.items())
        ]
        return 200, {"Content-Type": "application/json"}, json.dumps({"blocked": rows}).encode()

    if req["method"] == "POST" and req["path"] == "/v1/block":
        try:
            payload = json_body(req)
        except Exception:
            return 400, {"Content-Type": "text/plain"}, b"invalid json\n"
        ip = (payload or {}).get("ip")
        if not isinstance(ip, str) or not ip:
            return 400, {"Content-Type": "text/plain"}, b"ip required\n"
        ttl = int((payload or {}).get("ttl_s") or 21600)
        ok, err = await block(ip, ttl)
        if ok:
            print(f"fw_agent(k8s): blocked {ip} for {ttl}s", flush=True)
        return (
            (200 if ok else 500),
            {"Content-Type": "application/json"},
            json.dumps({"ok": ok, "ip": ip, "ttl_s": ttl, "error": None if ok else err}).encode(),
        )

    if req["method"] == "POST" and req["path"] == "/v1/unblock":
        try:
            payload = json_body(req)
        except Exception:
            return 400, {"Content-Type": "text/plain"}, b"invalid json\n"
        ip = (payload or {}).get("ip")
        if not isinstance(ip, str) or not ip:
            return 400, {"Content-Type": "text/plain"}, b"ip required\n"
        ok, err = await unblock(ip)
        return (
            (200 if ok else 500),
            {"Content-Type": "application/json"},
            json.dumps({"ok": ok, "ip": ip, "error": None if ok else err}).encode(),
        )

    return 404, {"Content-Type": "text/plain"}, b"not found\n"


async def main() -> None:
    _load_state()
    print(f"fw_agent(k8s) starting: policy={POLICY_NAME} blocked={len(_blocked)}", flush=True)
    if _blocked:
        ok, err = await _apply_locked()
        if not ok:
            print(f"fw_agent(k8s): initial apply failed: {err}", flush=True)
    asyncio.create_task(sweeper())
    server = await serve(BIND, PORT, handler, name="fw-agent-k8s")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
