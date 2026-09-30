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
    processes: list[dict[str, Any]] = field(default_factory=list)
    network: dict[str, Any] = field(default_factory=dict)
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
            processes=list(raw.get("processes") or []),
            network=dict(raw.get("network") or {}),
            visible=bool(raw.get("visible", True)),
            fqdn=str(raw.get("fqdn", "")),
        )

    def write_file(self, path: str, content: str, *, canary: bool = False, artifact_id: str | None = None) -> None:
        """Inject a virtual file (used by adaptive deception actions)."""
        p = "/" if path == "/" else path.rstrip("/") or "/"
        # Ensure parent directories exist in the virtual FS index
        parts = [x for x in p.split("/") if x]
        cur = ""
        for part in parts[:-1]:
            cur = f"{cur}/{part}"
            if cur not in self.filesystem:
                self.filesystem[cur] = {"type": "dir"}
        meta: dict[str, Any] = {"type": "file", "content": content}
        if canary:
            meta["canary"] = True
            meta["artifact_id"] = artifact_id or "canary"
        self.filesystem[p] = meta

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
    verbose_telemetry: bool = False
    canary_paths: set[str] = field(default_factory=set)
    revealed_segments: list[dict[str, Any]] = field(default_factory=list)
    deception_log: list[str] = field(default_factory=list)
    # Live FS / package theater — drives RAG rebuild + actor profiling
    created_paths: list[str] = field(default_factory=list)
    deleted_paths: list[str] = field(default_factory=list)
    packages_attempted: list[str] = field(default_factory=list)
    # Injected by pipeline/honeypot: multi-actor profile RAG snippets
    profile_rag_docs: list[dict[str, Any]] = field(default_factory=list)
    # Per-command mutation batch (reset at start of each execute)
    last_created: list[str] = field(default_factory=list)
    last_deleted: list[str] = field(default_factory=list)
    last_packages: list[str] = field(default_factory=list)
    # Phase-1 sandbox job log (feeds actor RAG)
    sandbox_jobs: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.user:
            self.user = self.host.default_user
        if self.cwd == "/":
            self.cwd = self.host.default_cwd()

    def begin_mutation_batch(self) -> None:
        self.last_created = []
        self.last_deleted = []
        self.last_packages = []

    @property
    def is_root(self) -> bool:
        return self.user == "root"

    def shell_prompt(self) -> str:
        """Bash-like prompt; `#` after sudo elevation."""
        mark = "#" if self.is_root else "$"
        return f"{self.user}@{self.host.hostname}:{self.cwd}{mark} "

    def note_created(self, path: str) -> None:
        p = path if path == "/" else path.rstrip("/") or "/"
        if p not in self.created_paths:
            self.created_paths.append(p)
        if p in self.deleted_paths:
            self.deleted_paths = [x for x in self.deleted_paths if x != p]
        if p not in self.last_created:
            self.last_created.append(p)

    def note_deleted(self, path: str) -> None:
        p = path if path == "/" else path.rstrip("/") or "/"
        if p not in self.deleted_paths:
            self.deleted_paths.append(p)
        self.created_paths = [x for x in self.created_paths if x != p and not x.startswith(p.rstrip("/") + "/")]
        if p not in self.last_deleted:
            self.last_deleted.append(p)

    def note_package(self, name: str) -> None:
        if name and name not in self.packages_attempted:
            self.packages_attempted.append(name)
        if name and name not in self.last_packages:
            self.last_packages.append(name)
