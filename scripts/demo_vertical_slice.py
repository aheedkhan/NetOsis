"""End-to-end demo: discovery → progressive deception D01–D07 (no LLM)."""

from __future__ import annotations

import argparse
import json
import os
import uuid
from pathlib import Path

from attack_graph.model.graph import AttackGraph
from deception.runtime.host import Session, VirtualHost
from deception.runtime.pipeline import VerticalSlicePipeline
from telemetry.storage.jsonl import JsonlTelemetryStore

ROOT = Path(__file__).resolve().parents[1]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="NetOsis adaptive deception demo")
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=Path(os.environ.get("NETOSIS_DATA_DIR", ROOT / "data")),
    )
    args = parser.parse_args(argv)

    host_path = Path(
        os.environ.get("NETOSIS_HOST_CONFIG", ROOT / "deception/hosts/enterprise-web.yml")
    )
    second_path = Path(
        os.environ.get("NETOSIS_SECOND_HOST", ROOT / "deception/hosts/finance-db.yml")
    )

    data_dir = args.data_dir
    data_dir.mkdir(parents=True, exist_ok=True)
    store = JsonlTelemetryStore(data_dir / "telemetry.jsonl")
    if store.path.exists():
        store.path.unlink()

    graph = AttackGraph()
    session = Session(
        host=VirtualHost.load(host_path),
        session_id=str(uuid.uuid4()),
        actor_id="demo-attacker",
        source_ip="203.0.113.50",
    )
    pipeline = VerticalSlicePipeline(
        session=session,
        store=store,
        graph=graph,
        second_host_path=second_path,
    )

    scripted = [
        "whoami",
        "pwd",
        "ls",
        "ps",
        "ip addr",
        "ip route",
        "cat notes.txt",
        "ls Documents",
        "cat Documents/VPN_Migration_Steps_2024.txt",
        "ip route",
    ]

    print("=== NetOsis adaptive deception demo ===")
    print(f"Host: {session.host.hostname} ({session.host.ip})")
    print()

    for line in scripted:
        print(f"$ {line}")
        result, event, decision = pipeline.run_command(line)
        if result.stdout:
            print(result.stdout, end="" if result.stdout.endswith("\n") else "\n")
        if result.stderr:
            print(result.stderr, end="" if result.stderr.endswith("\n") else "\n")
        tech = event.technique or "—"
        print(
            f"  → ATT&CK: {tech} ({event.technique_name or 'n/a'}) "
            f"conf={event.technique_confidence:.2f}"
        )
        print(
            f"  → policy: score={decision.risk_score} level={decision.level} "
            f"action={decision.action or 'none'} ({decision.reason})"
        )
        print()

    graph_path = data_dir / "attack_graph.json"
    graph.save(graph_path)
    profile_path = data_dir / "actor_profile.json"
    profile_path.write_text(
        json.dumps(pipeline.profile.summary(), indent=2),
        encoding="utf-8",
    )

    print("=== Outcomes ===")
    print(f"Triggered actions: {sorted(pipeline.triggered)}")
    print(f"Telemetry events: {len(pipeline.events)} → {store.path}")
    print(f"Graph nodes: {len(graph.nodes)} edges: {len(graph.edges)} → {graph_path}")
    print(f"Actor profile → {profile_path}")
    print(json.dumps(pipeline.profile.summary(), indent=2))
    if pipeline.exposed_host:
        h = pipeline.exposed_host
        print(f"D01 exposed host: {h.hostname} ({h.ip})")
    if session.verbose_telemetry:
        print("D06 verbose telemetry: ON")
    if session.revealed_segments:
        print(f"D07 segments: {[s.get('name') for s in session.revealed_segments]}")

    required = {"D01", "D02", "D03", "D04", "D05"}
    if not required.issubset(pipeline.triggered):
        print(f"Missing actions: {required - pipeline.triggered}")
        return 1

    print("Done — no LLM used.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
