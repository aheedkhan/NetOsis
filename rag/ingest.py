"""Chunk virtual host / deception knowledge into RAG documents.

Inspired by NVIDIA RAG Blueprint ingest stage (scaled down: no SeaweedFS/OCR).
Authoritative host facts remain YAML state; rag/corpus/ adds supplemental lore.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from deception.runtime.host import Session

ROOT = Path(__file__).resolve().parent  # .../rag
DEFAULT_CORPUS_DIR = ROOT / "corpus"
PROJECT_ROOT = ROOT.parent


@dataclass
class RagDocument:
    doc_id: str
    text: str
    metadata: dict[str, Any]


def _file_snippet(path: str, meta: dict[str, Any], *, max_chars: int = 400) -> str:
    content = str(meta.get("content", ""))[:max_chars]
    flags = []
    if meta.get("canary"):
        flags.append("sensitive")
    tag = f" [{','.join(flags)}]" if flags else ""
    return f"File {path}{tag}:\n{content}".strip()


def load_static_corpus(corpus_dir: Path | None = None) -> list[RagDocument]:
    """Load Antigravity (or human) markdown/text docs from rag/corpus/."""
    directory = corpus_dir or DEFAULT_CORPUS_DIR
    if not directory.is_dir():
        return []
    docs: list[RagDocument] = []
    for path in sorted(directory.iterdir()):
        if path.name.upper() == "README.MD" or path.name.startswith("."):
            continue
        if path.suffix.lower() not in {".md", ".txt"}:
            continue
        text = path.read_text(encoding="utf-8").strip()
        if not text:
            continue
        # Keep chunks bounded for CPU embedding
        if len(text) > 3000:
            text = text[:3000] + "\n…"
        docs.append(
            RagDocument(
                doc_id=f"corpus:{path.stem}",
                text=text,
                metadata={"type": "corpus", "path": str(path.relative_to(PROJECT_ROOT))},
            )
        )
    return docs


def build_corpus(
    session: Session,
    *,
    corpus_dir: Path | None = None,
    include_static: bool = True,
) -> list[RagDocument]:
    """Ingest session virtual state (+ optional rag/corpus lore) into documents."""
    host = session.host
    docs: list[RagDocument] = []

    docs.append(
        RagDocument(
            doc_id="host.identity",
            text=(
                f"Host {host.hostname} ({host.fqdn or host.hostname}) runs {host.os}. "
                f"Role {host.role}. VLAN {host.vlan}. IP {host.ip}. Gateway {host.gateway}. "
                f"Current user {session.user}. CWD {session.cwd}."
            ),
            metadata={"type": "identity", "hostname": host.hostname},
        )
    )

    if host.services:
        svc = ", ".join(f"{s.get('name')} on port {s.get('port')}" for s in host.services)
        docs.append(
            RagDocument(
                doc_id="host.services",
                text=f"Listening services on {host.hostname}: {svc}.",
                metadata={"type": "services"},
            )
        )

    if host.processes:
        procs = "; ".join(
            f"pid {p.get('pid')} user {p.get('user')} cmd {p.get('cmd')}"
            for p in host.processes[:12]
        )
        docs.append(
            RagDocument(
                doc_id="host.processes",
                text=f"Process table snapshot: {procs}.",
                metadata={"type": "processes"},
            )
        )

    net = host.network or {}
    ifaces = net.get("interfaces") or []
    if ifaces:
        lines = []
        for iface in ifaces:
            lines.append(
                f"{iface.get('name')} addresses {', '.join(iface.get('addresses') or [])}"
            )
        docs.append(
            RagDocument(
                doc_id="host.network.interfaces",
                text="Network interfaces: " + "; ".join(lines) + ".",
                metadata={"type": "network"},
            )
        )
    routes = net.get("routes") or []
    if routes:
        rlines = []
        for route in routes:
            gw = route.get("gateway")
            dest = route.get("destination")
            dev = route.get("dev")
            rlines.append(f"{dest} via {gw} dev {dev}" if gw else f"{dest} dev {dev}")
        docs.append(
            RagDocument(
                doc_id="host.network.routes",
                text="Routing table: " + "; ".join(rlines) + ".",
                metadata={"type": "network"},
            )
        )

    for path, meta in sorted(host.filesystem.items()):
        kind = meta.get("type", "file")
        if kind == "dir":
            origin = "attacker-created" if path in session.created_paths else "baseline"
            docs.append(
                RagDocument(
                    doc_id=f"fsdir:{path}",
                    text=f"Directory {path} exists on {host.hostname} ({origin}).",
                    metadata={"type": "dir", "path": path, "origin": origin},
                )
            )
            continue
        if kind != "file":
            continue
        origin = "attacker-created" if path in session.created_paths else "baseline"
        docs.append(
            RagDocument(
                doc_id=f"fs:{path}",
                text=_file_snippet(path, meta) + f"\n(origin: {origin})",
                metadata={
                    "type": "file",
                    "path": path,
                    "canary": bool(meta.get("canary")),
                    "origin": origin,
                },
            )
        )

    if session.created_paths or session.deleted_paths or session.packages_attempted:
        docs.append(
            RagDocument(
                doc_id=f"actor.mutations:{session.actor_id}",
                text=(
                    f"CURRENT attacker {session.actor_id} ({session.source_ip}) mutations "
                    f"on {host.hostname}. "
                    f"Created paths: {', '.join(session.created_paths) or '(none)'}. "
                    f"Deleted paths: {', '.join(session.deleted_paths) or '(none)'}. "
                    f"Packages they tried to install (theater): "
                    f"{', '.join(session.packages_attempted) or '(none)'}."
                ),
                metadata={
                    "type": "actor_profile",
                    "actor_id": session.actor_id,
                    "is_current": True,
                },
            )
        )

    # Persisted multi-hacker profiles (current + others, clearly labeled)
    profile_docs = getattr(session, "profile_rag_docs", None) or []
    for pd in profile_docs:
        docs.append(
            RagDocument(
                doc_id=str(pd["doc_id"]),
                text=str(pd["text"]),
                metadata=dict(pd.get("metadata") or {}),
            )
        )

    if session.exposed_hosts:
        docs.append(
            RagDocument(
                doc_id="deception.exposed_hosts",
                text="Recently discovered hosts: " + ", ".join(session.exposed_hosts) + ".",
                metadata={"type": "deception"},
            )
        )

    for idx, seg in enumerate(session.revealed_segments):
        peers = ", ".join(
            f"{p.get('hostname')}={p.get('ip')}" for p in (seg.get("peers") or [])
        )
        docs.append(
            RagDocument(
                doc_id=f"deception.segment.{idx}",
                text=(
                    f"Network segment {seg.get('name')} VLAN {seg.get('vlan')} "
                    f"subnet {seg.get('subnet')} gateway {seg.get('gateway')}. Peers: {peers}."
                ),
                metadata={"type": "segment"},
            )
        )

    if include_static:
        docs.extend(load_static_corpus(corpus_dir))

    return docs
