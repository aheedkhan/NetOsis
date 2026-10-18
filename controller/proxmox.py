"""Minimal Proxmox VE REST client (stdlib only — urllib, like openai_client.py).

Needs a restricted API token, NOT root password:

  pveum user add netosis-ctl@pve
  pveum aclmod /nodes/vhos/lxc/102 -user netosis-ctl@pve -role PVEVMAdmin
  pveum aclmod /nodes/vhos/lxc/104 -user netosis-ctl@pve -role PVEVMAdmin
  pveum aclmod /nodes/vhos/lxc/105 -user netosis-ctl@pve -role PVEVMAdmin
  pveum user token add netosis-ctl@pve ctl --privsep 0

PVEVMAdmin on just those three CTIDs is enough to start/stop/query them — the
token cannot touch the Jbox, OPNsense, Kali, itself, or any other node object.
Put the resulting token id/secret in controller/.env (never committed):

  PROXMOX_HOST=172.30.226.7:8006
  PROXMOX_NODE=vhos
  PROXMOX_TOKEN_ID=netosis-ctl@pve!ctl
  PROXMOX_TOKEN_SECRET=<uuid from token add>
  PROXMOX_VERIFY_SSL=0        # lab host uses Proxmox's self-signed cert
"""

from __future__ import annotations

import json
import os
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass


class ProxmoxError(RuntimeError):
    pass


@dataclass
class ProxmoxClient:
    host: str
    node: str
    token_id: str
    token_secret: str
    verify_ssl: bool = True

    @classmethod
    def from_env(cls) -> "ProxmoxClient":
        host = os.environ.get("PROXMOX_HOST", "")
        token_id = os.environ.get("PROXMOX_TOKEN_ID", "")
        token_secret = os.environ.get("PROXMOX_TOKEN_SECRET", "")
        if not (host and token_id and token_secret):
            raise ProxmoxError(
                "PROXMOX_HOST / PROXMOX_TOKEN_ID / PROXMOX_TOKEN_SECRET not set — "
                "see controller/proxmox.py docstring"
            )
        return cls(
            host=host,
            node=os.environ.get("PROXMOX_NODE", "vhos"),
            token_id=token_id,
            token_secret=token_secret,
            verify_ssl=os.environ.get("PROXMOX_VERIFY_SSL", "0").strip().lower() not in {"0", "false", "no"},
        )

    def _ctx(self) -> ssl.SSLContext | None:
        if self.verify_ssl:
            return None
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def _request(self, method: str, path: str, *, timeout: float = 10.0) -> dict:
        url = f"https://{self.host}/api2/json{path}"
        req = urllib.request.Request(
            url, method=method,
            headers={"Authorization": f"PVEAPIToken={self.token_id}={self.token_secret}"},
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=self._ctx()) as resp:
                body = json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise ProxmoxError(f"Proxmox HTTP {exc.code} on {method} {path}: {detail}") from exc
        except urllib.error.URLError as exc:
            raise ProxmoxError(f"Proxmox unreachable at {self.host}: {exc}") from exc
        return body.get("data") or {}

    def ct_status(self, ctid: int) -> str:
        """'running' | 'stopped' | ... (lxc only — honeypots are all CTs)."""
        data = self._request("GET", f"/nodes/{self.node}/lxc/{ctid}/status/current")
        return str(data.get("status", "unknown"))

    def ct_start(self, ctid: int) -> None:
        self._request("POST", f"/nodes/{self.node}/lxc/{ctid}/status/start")
