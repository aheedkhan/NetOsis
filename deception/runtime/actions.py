from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from deception.runtime.host import Session, VirtualHost

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_STAGED = ROOT / "deception" / "artifacts" / "staged_actions.yml"


@lru_cache(maxsize=4)
def _load_staged(path_str: str) -> dict[str, Any]:
    with Path(path_str).open(encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def apply_action(
    action_id: str,
    session: Session,
    *,
    second_host_path: Path | None = None,
    staged_path: Path | None = None,
) -> dict[str, Any]:
    """Apply a deception action; return a small result dict for logging/graph."""
    staged = _load_staged(str(staged_path or DEFAULT_STAGED))
    host = session.host

    if action_id == "D01":
        if not second_host_path:
            return {"ok": False, "detail": "no second host configured"}
        exposed = VirtualHost.load(second_host_path)
        exposed.set_visible(True)
        session.exposed_hosts.append(exposed.hostname)
        session.deception_log.append("D01")
        return {
            "ok": True,
            "exposed_host": exposed,
            "hostname": exposed.hostname,
            "ip": exposed.ip,
        }

    if action_id == "D02":
        cfg = staged.get("D02_expose_fake_service") or {}
        service = dict(cfg.get("service") or {})
        process = dict(cfg.get("process") or {})
        if service:
            host.services.append(service)
        if process:
            host.processes.append(process)
        note_path = cfg.get("note_path")
        if note_path:
            host.write_file(str(note_path), str(cfg.get("note_content", "")))
        session.deception_log.append("D02")
        return {"ok": True, "service": service, "process": process}

    if action_id == "D03":
        cfg = staged.get("D03_expose_fake_credential") or {}
        path = str(cfg.get("path", "/home/admin/.config/ops/db.url"))
        host.write_file(path, str(cfg.get("content", "")))
        session.deception_log.append("D03")
        return {"ok": True, "path": path}

    if action_id == "D04":
        cfg = staged.get("D04_expose_fake_document") or {}
        path = str(cfg.get("path", "/home/admin/Documents/Q3_vendor_contacts.txt"))
        host.write_file(path, str(cfg.get("content", "")))
        session.deception_log.append("D04")
        return {"ok": True, "path": path}

    if action_id == "D05":
        cfg = staged.get("D05_deploy_canary") or {}
        path = str(cfg.get("path", "/home/admin/Documents/VPN_Migration_Steps_2024.txt"))
        artifact_id = str(cfg.get("artifact_id", "canary-doc-01"))
        host.write_file(
            path,
            str(cfg.get("content", "")),
            canary=True,
            artifact_id=artifact_id,
        )
        session.canary_paths.add(path)
        session.deception_log.append("D05")
        return {"ok": True, "path": path, "artifact_id": artifact_id}

    if action_id == "D06":
        session.verbose_telemetry = True
        session.deception_log.append("D06")
        return {"ok": True, "verbose_telemetry": True}

    if action_id == "D07":
        cfg = staged.get("D07_reveal_virtual_network_segment") or {}
        segment = {
            "name": cfg.get("segment_name"),
            "vlan": cfg.get("vlan"),
            "subnet": cfg.get("subnet"),
            "gateway": cfg.get("gateway"),
            "peers": list(cfg.get("peers") or []),
        }
        session.revealed_segments.append(segment)
        hosts_path = cfg.get("hosts_path")
        if hosts_path:
            host.write_file(str(hosts_path), str(cfg.get("hosts_content", "")))
        # Extend virtual routing table with FINANCE route hint
        routes = host.network.setdefault("routes", [])
        routes.append(
            {
                "destination": cfg.get("subnet", "192.168.10.0/24"),
                "gateway": host.gateway,
                "dev": "eth0",
            }
        )
        session.deception_log.append("D07")
        return {"ok": True, "segment": segment}

    return {"ok": False, "detail": f"unknown action {action_id}"}
