from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class AttackGraph:
    """Simple directed multigraph stored as nodes + edges."""

    nodes: dict[str, dict[str, Any]] = field(default_factory=dict)
    edges: list[dict[str, Any]] = field(default_factory=list)

    def add_node(self, node_id: str, **attrs: Any) -> None:
        if node_id not in self.nodes:
            self.nodes[node_id] = {"id": node_id, **attrs}
        else:
            self.nodes[node_id].update(attrs)

    def add_edge(self, source: str, target: str, relation: str, **attrs: Any) -> None:
        self.edges.append(
            {"source": source, "target": target, "relation": relation, **attrs}
        )

    def to_dict(self) -> dict[str, Any]:
        return {"nodes": list(self.nodes.values()), "edges": list(self.edges)}

    def save(self, path: str | Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path) -> AttackGraph:
        path = Path(path)
        if not path.exists():
            return cls()
        data = json.loads(path.read_text(encoding="utf-8"))
        graph = cls()
        for node in data.get("nodes") or []:
            nid = node["id"]
            graph.nodes[nid] = dict(node)
        graph.edges = list(data.get("edges") or [])
        return graph

    def apply_event(self, event: dict[str, Any]) -> None:
        actor = f"actor:{event.get('actor_id', 'unknown')}"
        host = f"host:{event.get('target_host', 'unknown')}"
        cmd = event.get("command") or ""
        tech = event.get("technique")

        self.add_node(actor, type="ACTOR")
        self.add_node(
            host,
            type="HOST",
            ip=event.get("target_ip"),
            hostname=event.get("target_host"),
        )
        self.add_edge(actor, host, "interacted_with", session_id=event.get("session_id"))

        if cmd:
            cmd_id = f"command:{event.get('session_id')}:{cmd}"
            self.add_node(cmd_id, type="COMMAND", command=cmd)
            self.add_edge(actor, cmd_id, "executed")
            if tech:
                tech_id = f"technique:{tech}"
                self.add_node(
                    tech_id,
                    type="ATT&CK_TECHNIQUE",
                    technique=tech,
                    name=event.get("technique_name"),
                )
                self.add_edge(
                    cmd_id,
                    tech_id,
                    "maps_to",
                    confidence=event.get("technique_confidence"),
                )
