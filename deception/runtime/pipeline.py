from __future__ import annotations

import os
from pathlib import Path

from attack_graph.model.graph import AttackGraph
from deception.command_engine.engine import CommandResult, execute
from deception.runtime.actions import apply_action
from deception.runtime.fs_risk import mutation_risk_category
from deception.runtime.host import Session
from deception.runtime.profile_store import ProfileStore
from mitre.mapper.mapper import map_command
from policy.engine.engine import PolicyDecision, evaluate
from telemetry.schema.events import TelemetryEvent, utc_now_iso
from telemetry.storage.jsonl import JsonlTelemetryStore


def _cat_target_path(session: Session, command: str) -> str | None:
    parts = command.strip().split()
    if len(parts) < 2 or parts[0] != "cat":
        return None
    target = parts[1]
    if target.startswith("/"):
        return target.rstrip("/") or "/"
    if session.cwd == "/":
        return f"/{target}".rstrip("/") or "/"
    return f"{session.cwd.rstrip('/')}/{target}"


class VerticalSlicePipeline:
    """Wire shell → telemetry → ATT&CK → graph → policy → deception.

    Native commands are deterministic. Unsupported commands may use a
    state-constrained LLM fallback (mock by default); policy remains authoritative.
    """

    def __init__(
        self,
        session: Session,
        store: JsonlTelemetryStore,
        graph: AttackGraph,
        second_host_path: Path | None = None,
        profile_store: ProfileStore | None = None,
    ) -> None:
        self.session = session
        self.store = store
        self.graph = graph
        self.second_host_path = second_host_path
        self.events: list[dict] = []
        self.triggered: set[str] = set()
        self.exposed_host = None
        self.last_decision: PolicyDecision | None = None
        data_root = Path(os.environ.get("NETOSIS_DATA_DIR", "data"))
        self.profile_store = profile_store or ProfileStore(data_root / "profiles")
        self.profile = self.profile_store.load(
            session.actor_id, source_ip=session.source_ip
        )
        if not session.created_paths and self.profile.paths_created:
            self.profile.restore_into_session(session)
        self.profile_store.save(self.profile)
        self._refresh_profile_rag_docs()
        self.action_results: list[dict] = []

    def _refresh_profile_rag_docs(self) -> None:
        include_others = os.environ.get("NETOSIS_RAG_MULTI_ACTOR", "1").strip().lower() not in {
            "0",
            "false",
            "no",
            "off",
        }
        # Save current first so list_profiles sees latest, then rebuild docs
        self.session.profile_rag_docs = self.profile_store.rag_docs(
            current_actor_id=self.session.actor_id,
            include_others=include_others,
        )

    def run_command(self, line: str) -> tuple[CommandResult, TelemetryEvent, PolicyDecision]:
        result = execute(self.session, line)
        mapping = map_command(result.command or line)

        risk_category = mapping.risk_category if mapping else None
        mut_cat = mutation_risk_category(self.session)
        if mut_cat:
            # Creating/deleting files & package theater outrank generic discovery.
            risk_category = mut_cat
        # Sandbox external fetch / payload
        if self.session.sandbox_jobs and self.session.sandbox_jobs[-1].get("command") == (
            result.command or line.strip()
        ):
            job = self.session.sandbox_jobs[-1]
            risk_category = (
                "Payload_transfer"
                if job.get("contained") or job.get("classification") == "malware"
                else "Package_install"
            )
            actor = f"actor:{self.session.actor_id}"
            sb_node = f"sandbox:{job.get('job_id')}"
            self.graph.add_node(
                sb_node,
                type="SANDBOX_JOB",
                classification=job.get("classification"),
                contained=job.get("contained"),
            )
            self.graph.add_edge(actor, sb_node, "sandbox_exec")
        # Canary access escalates category for policy scoring
        cat_path = _cat_target_path(self.session, result.command or line)
        if (
            result.exit_code == 0
            and cat_path
            and (cat_path in self.session.canary_paths
                 or (self.session.host.filesystem.get(cat_path) or {}).get("canary"))
        ):
            risk_category = "Canary_interaction"
            self.graph.add_edge(
                f"actor:{self.session.actor_id}",
                f"canary:{(self.session.host.filesystem.get(cat_path) or {}).get('artifact_id', cat_path)}",
                "triggered",
            )
            self.graph.add_node(
                f"canary:{(self.session.host.filesystem.get(cat_path) or {}).get('artifact_id', cat_path)}",
                type="CANARY",
                path=cat_path,
            )

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
            extra={
                "risk_category": risk_category,
                "llm_fallback": bool(getattr(result, "llm_fallback", False)),
                **(
                    {
                        "created": list(self.session.last_created),
                        "deleted": list(self.session.last_deleted),
                        "packages": list(self.session.last_packages),
                    }
                    if (self.session.last_created or self.session.last_deleted or self.session.last_packages)
                    else {}
                ),
                **(
                    {"verbose": True, "cwd": self.session.cwd}
                    if self.session.verbose_telemetry
                    else {}
                ),
            },
        )
        payload = event.to_dict()
        if risk_category:
            payload["risk_category"] = risk_category
        self.store.append(event)
        self.events.append(payload)
        self.graph.apply_event(payload)

        decision = evaluate(self.events, already_triggered=self.triggered)
        self.last_decision = decision
        if decision.action and decision.action not in self.triggered:
            result_meta = apply_action(
                decision.action,
                self.session,
                second_host_path=self.second_host_path,
            )
            self.triggered.add(decision.action)
            self.action_results.append({"action": decision.action, **result_meta})
            self._record_action_on_graph(decision.action, result_meta)
            if decision.action == "D01" and result_meta.get("exposed_host") is not None:
                self.exposed_host = result_meta["exposed_host"]

        self.profile.observe(
            payload,
            risk_score=decision.risk_score,
            level=decision.level,
        )
        self.profile.sync_session_mutations(self.session)
        self.profile_store.save(self.profile)
        self._refresh_profile_rag_docs()
        return result, event, decision

    def _record_action_on_graph(self, action_id: str, meta: dict) -> None:
        actor = f"actor:{self.session.actor_id}"
        action_node = f"action:{action_id}"
        self.graph.add_node(action_node, type="DECEPTION_ACTION", action=action_id)
        self.graph.add_edge(actor, action_node, "triggered_policy")

        if action_id == "D01" and meta.get("hostname"):
            host_id = f"host:{meta['hostname']}"
            self.graph.add_node(
                host_id,
                type="HOST",
                ip=meta.get("ip"),
                hostname=meta["hostname"],
                exposed_by="D01",
                visible=True,
            )
            self.graph.add_edge(actor, host_id, "discovered", via="D01")
        elif action_id in {"D03", "D04", "D05"} and meta.get("path"):
            art = f"artifact:{meta['path']}"
            self.graph.add_node(art, type="ARTIFACT", path=meta["path"], via=action_id)
            self.graph.add_edge(actor, art, "accessed" if action_id != "D05" else "canary_deployed")
        elif action_id == "D07" and meta.get("segment"):
            seg = meta["segment"]
            seg_id = f"segment:{seg.get('name', 'unknown')}"
            self.graph.add_node(seg_id, type="VLAN", **{k: v for k, v in seg.items() if k != "peers"})
            self.graph.add_edge(actor, seg_id, "discovered", via="D07")
