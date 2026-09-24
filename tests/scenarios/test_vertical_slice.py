from __future__ import annotations

import uuid
from pathlib import Path

from attack_graph.model.graph import AttackGraph
from deception.runtime.host import Session, VirtualHost
from deception.runtime.pipeline import VerticalSlicePipeline
from telemetry.storage.jsonl import JsonlTelemetryStore

ROOT = Path(__file__).resolve().parents[2]


def test_vertical_slice_triggers_d01(tmp_path: Path) -> None:
    store = JsonlTelemetryStore(tmp_path / "telemetry.jsonl")
    graph = AttackGraph()
    session = Session(
        host=VirtualHost.load(ROOT / "deception/hosts/enterprise-web.yml"),
        session_id=str(uuid.uuid4()),
        actor_id="test-actor",
    )
    pipeline = VerticalSlicePipeline(
        session=session,
        store=store,
        graph=graph,
        second_host_path=ROOT / "deception/hosts/finance-db.yml",
    )

    for line in ("whoami", "pwd", "ls", "cat notes.txt"):
        pipeline.run_command(line)

    assert len(pipeline.events) == 4
    assert all(e.get("technique") for e in pipeline.events)
    assert "D01" in pipeline.triggered
    assert pipeline.exposed_host is not None
    assert pipeline.exposed_host.hostname == "finance-db-01"
    assert pipeline.exposed_host.visible is True
    assert any(n.get("type") == "ATT&CK_TECHNIQUE" for n in graph.nodes.values())
    assert store.read_all()  # persisted
