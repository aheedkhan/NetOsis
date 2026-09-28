"""Persist and load per-attacker profiles for multi-hacker RAG."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from deception.runtime.actor_profile import ActorProfile


def _safe_actor_filename(actor_id: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", actor_id).strip("._") or "unknown"
    return f"{cleaned}.json"


class ProfileStore:
    """One JSON file per actor under data/profiles/."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def path_for(self, actor_id: str) -> Path:
        return self.root / _safe_actor_filename(actor_id)

    def load(self, actor_id: str, *, source_ip: str = "") -> ActorProfile:
        path = self.path_for(actor_id)
        if not path.is_file():
            return ActorProfile(actor_id=actor_id, source_ip=source_ip or "0.0.0.0")
        raw = json.loads(path.read_text(encoding="utf-8"))
        return ActorProfile.from_summary(raw, default_source_ip=source_ip)

    def save(self, profile: ActorProfile) -> Path:
        path = self.path_for(profile.actor_id)
        path.write_text(json.dumps(profile.summary(), indent=2), encoding="utf-8")
        return path

    def list_profiles(self) -> list[ActorProfile]:
        out: list[ActorProfile] = []
        for path in sorted(self.root.glob("*.json")):
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            out.append(ActorProfile.from_summary(raw))
        return out

    def rag_docs(
        self,
        *,
        current_actor_id: str,
        include_others: bool = True,
    ) -> list[dict[str, Any]]:
        """Build RAG-oriented dicts: current actor full, others labeled separately."""
        docs: list[dict[str, Any]] = []
        for profile in self.list_profiles():
            is_current = profile.actor_id == current_actor_id
            if not is_current and not include_others:
                continue
            docs.append(
                {
                    "doc_id": f"actor_profile:{profile.actor_id}",
                    "text": profile.to_rag_text(is_current=is_current),
                    "metadata": {
                        "type": "actor_profile",
                        "actor_id": profile.actor_id,
                        "is_current": is_current,
                    },
                }
            )
        return docs
