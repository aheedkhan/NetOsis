from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class VirtualHost:
    """Authoritative emulated host state loaded from YAML."""

    path: Path
    raw: dict[str, Any]
    hostname: str
    role: str
    os: str
    vlan: int
    ip: str
    gateway: str
    users: list[dict[str, Any]]
    default_user: str
    filesystem: dict[str, dict[str, Any]]
    services: list[dict[str, Any]]
    visible: bool = True
    fqdn: str = ""

    @classmethod
    def load(cls, path: str | Path) -> VirtualHost:
        path = Path(path)
        with path.open(encoding="utf-8") as fh:
            raw = yaml.safe_load(fh) or {}
        fs = raw.get("filesystem") or {}
        # Normalize keys to absolute posix paths without trailing slash (except /)
        normalized: dict[str, dict[str, Any]] = {}
        for key, meta in fs.items():
            p = "/" if key == "/" else key.rstrip("/") or "/"
            normalized[p] = meta if isinstance(meta, dict) else {"type": "file", "content": str(meta)}
        return cls(
            path=path,
            raw=raw,
            hostname=str(raw.get("hostname", "unknown")),
            role=str(raw.get("role", "")),
            os=str(raw.get("os", "")),
            vlan=int(raw.get("vlan", 0)),
            ip=str(raw.get("ip", "")),
            gateway=str(raw.get("gateway", "")),
            users=list(raw.get("users") or []),
            default_user=str(raw.get("default_user", "root")),
            filesystem=normalized,
            services=list(raw.get("services") or []),
            visible=bool(raw.get("visible", True)),
            fqdn=str(raw.get("fqdn", "")),
        )

    def set_visible(self, visible: bool) -> None:
        self.visible = visible
        self.raw["visible"] = visible

    def default_cwd(self) -> str:
        configured = self.raw.get("cwd")
        if configured:
            return str(configured)
        for user in self.users:
            if user.get("name") == self.default_user:
                return str(user.get("home", "/"))
        return "/"


@dataclass
class Session:
    """Interactive shell session bound to one virtual host."""

    host: VirtualHost
    session_id: str
    actor_id: str = "actor-local"
    source_ip: str = "127.0.0.1"
    user: str = ""
    cwd: str = "/"
    exposed_hosts: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.user:
            self.user = self.host.default_user
        if self.cwd == "/":
            self.cwd = self.host.default_cwd()
