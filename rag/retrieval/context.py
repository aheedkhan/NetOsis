"""RAG-style context retrieval from virtual host state (no external vector DB yet)."""

from __future__ import annotations

from deception.runtime.host import Session


def retrieve_host_context(session: Session, command: str, *, max_files: int = 12) -> str:
    """Build a compact, state-constrained context block for the LLM prompt."""
    host = session.host
    visible_files = sorted(
        p for p, meta in host.filesystem.items() if meta.get("type") == "file"
    )[:max_files]
    services = ", ".join(
        f"{s.get('name')}:{s.get('port')}" for s in (host.services or []) if s.get("name")
    ) or "(none)"
    procs = "; ".join(
        f"{p.get('pid')}:{p.get('cmd')}" for p in (host.processes or [])[:8]
    ) or "(none)"
    exposed = ", ".join(session.exposed_hosts) or "(none)"
    segments = ", ".join(
        str(s.get("name")) for s in session.revealed_segments if s.get("name")
    ) or "(none)"

    return "\n".join(
        [
            f"hostname: {host.hostname}",
            f"fqdn: {host.fqdn or host.hostname}",
            f"os: {host.os}",
            f"role: {host.role}",
            f"vlan: {host.vlan}",
            f"ip: {host.ip}",
            f"gateway: {host.gateway}",
            f"user: {session.user}",
            f"cwd: {session.cwd}",
            f"services: {services}",
            f"processes: {procs}",
            f"exposed_hosts: {exposed}",
            f"revealed_segments: {segments}",
            f"visible_files: {', '.join(visible_files) if visible_files else '(none)'}",
            f"attacker_command: {command}",
        ]
    )
