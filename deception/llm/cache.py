"""Persistent LLM response cache.

The same command on the same host/user always returns the same output, so the
fake shell stays consistent and repeated commands answer instantly. The cache
can be pre-filled offline by a larger model (scripts/llm_prewarm.py) while the
live honeypot falls back to a small model only for commands never seen before.

Enabled with NETOSIS_LLM_CACHE=1; file: $NETOSIS_DATA_DIR/llm_cache.json.
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path

from deception.runtime.host import Session

_LOCK = threading.Lock()


def cache_enabled() -> bool:
    return os.environ.get("NETOSIS_LLM_CACHE", "0").strip().lower() in {"1", "true", "yes", "on"}


def cache_path() -> Path:
    return Path(os.environ.get("NETOSIS_DATA_DIR", "data")) / "llm_cache.json"


def cache_key(session: Session, command: str) -> str:
    return f"{session.host.hostname}|{session.user}|{' '.join(command.split())}"


class ResponseCache:
    """JSON file shared by the honeypot service and the pre-warm script."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._data: dict[str, str] = {}
        self._mtime = 0.0

    def _reload_if_changed(self) -> None:
        try:
            mtime = self.path.stat().st_mtime
        except FileNotFoundError:
            return
        if mtime == self._mtime:
            return
        try:
            self._data = json.loads(self.path.read_text(encoding="utf-8"))
            self._mtime = mtime
        except (OSError, json.JSONDecodeError):
            pass

    def get(self, key: str) -> str | None:
        with _LOCK:
            self._reload_if_changed()
            return self._data.get(key)

    def put(self, key: str, text: str) -> None:
        with _LOCK:
            self._reload_if_changed()  # keep entries written by the other process
            self._data[key] = text
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                tmp = self.path.with_suffix(".tmp")
                tmp.write_text(json.dumps(self._data, indent=1, sort_keys=True), encoding="utf-8")
                tmp.replace(self.path)
                self._mtime = self.path.stat().st_mtime
            except OSError as exc:  # read-only/foreign-owned file must not break the shell
                print(f"  [llm-cache] write failed: {exc}")

    def __len__(self) -> int:
        with _LOCK:
            self._reload_if_changed()
            return len(self._data)


_INSTANCES: dict[Path, ResponseCache] = {}


def get_cache() -> ResponseCache | None:
    if not cache_enabled():
        return None
    path = cache_path().resolve()
    with _LOCK:
        if path not in _INSTANCES:
            _INSTANCES[path] = ResponseCache(path)
        return _INSTANCES[path]
