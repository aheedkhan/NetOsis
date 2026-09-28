"""Per-attacker behavioral profile — one hacker ≠ another in RAG."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ActorProfile:
    """Explainable profile for one attacker (keyed by actor_id / source IP)."""

    actor_id: str
    source_ip: str
    commands: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    behaviors: list[str] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    canary_hits: int = 0
    risk_score: float = 0.0
    level: str = "LOW"
    paths_created: list[str] = field(default_factory=list)
    paths_deleted: list[str] = field(default_factory=list)
    packages_attempted: list[str] = field(default_factory=list)
    # Virtual FS artifacts this actor created (for restore + RAG)
    artifacts: list[dict[str, Any]] = field(default_factory=list)

    def observe(self, event: dict[str, Any], risk_score: float, level: str) -> None:
        cmd = event.get("command")
        if cmd:
            self.commands.append(str(cmd))
            # Cap history so profiles stay small
            if len(self.commands) > 80:
                self.commands = self.commands[-80:]
        tech = event.get("technique")
        if tech and tech not in self.techniques:
            self.techniques.append(str(tech))
        behavior = event.get("behavior")
        if behavior and behavior not in self.behaviors:
            self.behaviors.append(str(behavior))
        category = event.get("risk_category")
        if category and category not in self.categories:
            self.categories.append(str(category))
        if category == "Canary_interaction":
            self.canary_hits += 1
        self.risk_score = risk_score
        self.level = level

    def sync_session_mutations(self, session: Any) -> None:
        """Mirror live FS/package theater from Session into the profile."""
        self.paths_created = list(getattr(session, "created_paths", []) or [])
        self.paths_deleted = list(getattr(session, "deleted_paths", []) or [])
        self.packages_attempted = list(getattr(session, "packages_attempted", []) or [])
        arts: list[dict[str, Any]] = []
        fs = getattr(getattr(session, "host", None), "filesystem", {}) or {}
        for path in self.paths_created:
            meta = fs.get(path) or {}
            entry: dict[str, Any] = {
                "path": path,
                "type": meta.get("type", "file"),
            }
            if entry["type"] == "file":
                entry["content"] = str(meta.get("content", ""))[:500]
            arts.append(entry)
        self.artifacts = arts

    def restore_into_session(self, session: Any) -> None:
        """Re-apply this actor's prior FS theater onto a fresh session host."""
        session.created_paths = list(self.paths_created)
        session.deleted_paths = list(self.paths_deleted)
        session.packages_attempted = list(self.packages_attempted)
        fs = session.host.filesystem
        for art in self.artifacts:
            path = str(art.get("path") or "")
            if not path or path in fs:
                continue
            kind = art.get("type", "file")
            if kind == "dir":
                fs[path] = {"type": "dir"}
            else:
                fs[path] = {"type": "file", "content": str(art.get("content") or "")}
            # Ensure parent dirs exist
            parts = [x for x in path.split("/") if x]
            cur = ""
            for part in parts[:-1]:
                cur = f"{cur}/{part}"
                if cur not in fs:
                    fs[cur] = {"type": "dir"}

    def summary(self) -> dict[str, Any]:
        return {
            "actor_id": self.actor_id,
            "source_ip": self.source_ip,
            "command_count": len(self.commands),
            "commands": list(self.commands[-40:]),
            "techniques": list(self.techniques),
            "behaviors": list(self.behaviors),
            "categories": list(self.categories),
            "canary_hits": self.canary_hits,
            "risk_score": self.risk_score,
            "level": self.level,
            "paths_created": list(self.paths_created),
            "paths_deleted": list(self.paths_deleted),
            "packages_attempted": list(self.packages_attempted),
            "artifacts": list(self.artifacts),
        }

    @classmethod
    def from_summary(
        cls, raw: dict[str, Any], *, default_source_ip: str = ""
    ) -> ActorProfile:
        return cls(
            actor_id=str(raw.get("actor_id") or "unknown"),
            source_ip=str(raw.get("source_ip") or default_source_ip or "0.0.0.0"),
            commands=list(raw.get("commands") or []),
            techniques=list(raw.get("techniques") or []),
            behaviors=list(raw.get("behaviors") or []),
            categories=list(raw.get("categories") or []),
            canary_hits=int(raw.get("canary_hits") or 0),
            risk_score=float(raw.get("risk_score") or 0.0),
            level=str(raw.get("level") or "LOW"),
            paths_created=list(raw.get("paths_created") or []),
            paths_deleted=list(raw.get("paths_deleted") or []),
            packages_attempted=list(raw.get("packages_attempted") or []),
            artifacts=list(raw.get("artifacts") or []),
        )

    def to_rag_text(self, *, is_current: bool) -> str:
        """Evidence blob for RAG — clearly labels current vs other attackers."""
        role = (
            "CURRENT ATTACKER on this shell session — attribute ALL shell state to them."
            if is_current
            else "OTHER attacker (do NOT mix their files/packages into this shell's replies)."
        )
        recent = self.commands[-12:]
        recent_s = "; ".join(recent) if recent else "(none yet)"
        arts = ", ".join(
            f"{a.get('path')}[{a.get('type')}]" for a in self.artifacts[:20]
        ) or "(none)"
        return (
            f"Actor profile [{self.actor_id}] source_ip={self.source_ip}. {role} "
            f"Risk {self.level} score={self.risk_score}. "
            f"Techniques: {', '.join(self.techniques) or '(none)'}. "
            f"Risk categories: {', '.join(self.categories) or '(none)'}. "
            f"Created paths: {', '.join(self.paths_created) or '(none)'}. "
            f"Deleted paths: {', '.join(self.paths_deleted) or '(none)'}. "
            f"Packages attempted (theater): {', '.join(self.packages_attempted) or '(none)'}. "
            f"Artifacts: {arts}. "
            f"Recent commands: {recent_s}."
        )
