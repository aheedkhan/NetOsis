from __future__ import annotations

from pathlib import Path

from attack_graph.model.graph import AttackGraph
from deception.command_engine.engine import CommandResult, execute
from deception.runtime.host import Session, VirtualHost
from mitre.mapper.mapper import map_command
from policy.engine.engine import PolicyDecision, evaluate
from telemetry.schema.events import TelemetryEvent, utc_now_iso
from telemetry.storage.jsonl import JsonlTelemetryStore


class VerticalSlicePipeline:
    """Wire shell → telemetry → ATT&CK → graph → policy (no LLM)."""

    def __init__(
        self,
        session: Session,
        store: JsonlTelemetryStore,
        graph: AttackGraph,
        second_host_path: Path | None = None,
    ) -> None:
        self.session = session
        self.store = store
        self.graph = graph
        self.second_host_path = second_host_path
        self.events: list[dict] = []
        self.triggered: set[str] = set()
        self.exposed_host: VirtualHost | None = None
        self.last_decision: PolicyDecision | None = None

    def run_command(self, line: str) -> tuple[CommandResult, TelemetryEvent, PolicyDecision]:
        result = execute(self.session, line)
        mapping = map_command(result.command or line)
        event = TelemetryEvent(
            timestamp=utc_now_iso(),
            session_id=self.session.session_id,
            actor_id=self.session.actor_id,
            source_ip=self.session.source_ip,
            target_host=self.session.host.hostname,
            target_ip=self.session.host.ip,
            event_type="command",
            command=result.command or line.strip(),
            result=(result.stdout or result.stderr).rstrip("\n"),
            virtual=True,
            technique=mapping.technique if mapping else None,
            technique_name=mapping.technique_name if mapping else None,
            technique_confidence=mapping.confidence if mapping else 0.0,
            behavior=mapping.behavior if mapping else None,
            extra={"risk_category": mapping.risk_category} if mapping else {},
        )
        payload = event.to_dict()
        if mapping:
            payload["risk_category"] = mapping.risk_category
        self.store.append(event)
        self.events.append(payload)
        self.graph.apply_event(payload)

        decision = evaluate(self.events, already_triggered=self.triggered)
        self.last_decision = decision
        if decision.action == "D01" and "D01" not in self.triggered:
            self._apply_d01()
            self.triggered.add("D01")
            self.graph.add_edge(
                f"actor:{self.session.actor_id}",
                f"host:{self.exposed_host.hostname if self.exposed_host else 'finance-db-01'}",
                "discovered",
                via="D01",
            )
        return result, event, decision

    def _apply_d01(self) -> None:
        if not self.second_host_path:
            return
        host = VirtualHost.load(self.second_host_path)
        host.set_visible(True)
        self.exposed_host = host
        self.session.exposed_hosts.append(host.hostname)
        self.graph.add_node(
            f"host:{host.hostname}",
            type="HOST",
            ip=host.ip,
            hostname=host.hostname,
            exposed_by="D01",
            visible=True,
        )
