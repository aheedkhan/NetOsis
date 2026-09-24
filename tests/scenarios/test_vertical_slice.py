from __future__ import annotations

import uuid
from pathlib import Path

from attack_graph.model.graph import AttackGraph
from deception.runtime.host import Session, VirtualHost
from deception.runtime.pipeline import VerticalSlicePipeline
from mitre.mapper.mapper import _load_mappings
from policy.engine.engine import clear_rules_cache
from telemetry.storage.jsonl import JsonlTelemetryStore

ROOT = Path(__file__).resolve().parents[2]


def _pipeline(tmp_path: Path) -> VerticalSlicePipeline:
    clear_rules_cache()
    _load_mappings.cache_clear()
    store = JsonlTelemetryStore(tmp_path / "telemetry.jsonl")
    graph = AttackGraph()
    session = Session(
        host=VirtualHost.load(ROOT / "deception/hosts/enterprise-web.yml"),
        session_id=str(uuid.uuid4()),
        actor_id="test-actor",
    )
    return VerticalSlicePipeline(
        session=session,
        store=store,
        graph=graph,
        second_host_path=ROOT / "deception/hosts/finance-db.yml",
    )


def test_vertical_slice_triggers_d01(tmp_path: Path) -> None:
    pipeline = _pipeline(tmp_path)
    for line in ("whoami", "pwd", "ls", "cat notes.txt"):
        pipeline.run_command(line)

    assert len(pipeline.events) == 4
    assert all(e.get("technique") for e in pipeline.events)
    assert "D01" in pipeline.triggered
    assert pipeline.exposed_host is not None
    assert pipeline.exposed_host.hostname == "finance-db-01"
    assert pipeline.exposed_host.visible is True
    assert any(n.get("type") == "ATT&CK_TECHNIQUE" for n in pipeline.graph.nodes.values())
    assert pipeline.store.read_all()


def test_progressive_deception_ladder(tmp_path: Path) -> None:
    pipeline = _pipeline(tmp_path)
    for line in (
        "whoami",
        "pwd",
        "ls",
        "ps",
        "ip addr",
        "ip route",
        "cat notes.txt",
        "ls /home/admin",
        "cat Documents/VPN_Migration_Steps_2024.txt",
        "ps",
    ):
        pipeline.run_command(line)

    assert {"D01", "D02", "D03", "D04", "D05"}.issubset(pipeline.triggered)
    # D02 should have injected redis
    assert any(s.get("name") == "redis" for s in pipeline.session.host.services)
    # D03 credential file exists
    assert "/home/admin/.config/ops/db.url" in pipeline.session.host.filesystem
    # D05 canary registered
    assert pipeline.session.canary_paths
    # Actor profile collected techniques
    assert "T1033" in pipeline.profile.techniques
    assert len(pipeline.profile.commands) >= 8


def test_canary_interaction_scored(tmp_path: Path) -> None:
    pipeline = _pipeline(tmp_path)
    # Climb to D05
    for line in ("whoami", "pwd", "ls", "ps", "ip addr", "ip route", "cat notes.txt"):
        pipeline.run_command(line)
    assert "D05" in pipeline.triggered
    pipeline.run_command("cat Documents/VPN_Migration_Steps_2024.txt")
    assert any(e.get("risk_category") == "Canary_interaction" for e in pipeline.events)
    assert pipeline.profile.canary_hits >= 1
