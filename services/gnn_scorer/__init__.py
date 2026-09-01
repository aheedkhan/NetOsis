"""GNN-based dynamic scoring service — slow path, cached by decision plane."""

from __future__ import annotations

import json
import os
from typing import Any

from cs.belief import OBJECTIVES, default_intent
from cs.graph import build_graph
from cs.operator import classify
from cs.patterns import score as pattern_score
from cs.tinyhttp import json_body, serve

BIND = os.environ.get("CS_BIND", "0.0.0.0")
PORT = int(os.environ.get("CS_PORT", "9100"))
LOGGER_HOST = os.environ.get("CS_LOGGER_HOST", "10.200.1.10")
LOGGER_PORT = int(os.environ.get("CS_LOGGER_PORT", "8088"))

# In-memory event ring + score cache (refreshed on ingest).
_events: list[dict[str, Any]] = []
_scores: dict[str, dict[str, Any]] = {}
_model = None


def _load_model():
    """
    Load the trained checkpoint if one exists.

    A model without a checkpoint is returned but flagged untrained, and
    score_graph will refuse to use it — returning explicit priors instead of
    the sigmoid of random weights, which is what the previous version did.
    Train one with:  ./cs train-gnn
    """
    global _model
    if _model is not None:
        return _model
    try:
        from cs.gnn_model import load, score_graph

        model = load()
        state = "trained" if getattr(model, "trained", False) else "UNTRAINED (priors only)"
        print(f"gnn_scorer: model {state}", flush=True)
        _model = (model, score_graph)
    except ImportError:
        print("gnn_scorer: torch unavailable, using deterministic fallback", flush=True)
        _model = (None, _fallback_score)
    return _model


def _fallback_score(graph: dict[str, Any], actor_key: str) -> dict[str, Any]:
    """Deterministic fallback when PyTorch is unavailable."""
    nodes = graph.get("nodes") or []
    actor_node = next((n for n in nodes if n.get("key") == actor_key), None)
    events = float((actor_node or {}).get("events") or 0)
    ds = len((actor_node or {}).get("datasets") or [])
    intel = min(1.0, 0.3 + events / 40.0 + ds / 12.0)
    suspicion = min(1.0, 0.05 + ds * 0.02)
    novelty = max(0.05, 1.0 - events / 60.0)
    intent = default_intent()
    if ds > 3:
        intent["credential_spray"] = 0.35
        intent["recon_scan"] = 0.25
        intent["unknown"] = 0.15
    _normalize(intent)
    return {
        "actor_key": actor_key,
        "intel_gain": intel,
        "suspicion": suspicion,
        "novelty": novelty,
        "intent": intent,
        "model": "fallback",
    }


def _normalize(intent: dict[str, float]) -> None:
    total = sum(intent.values()) or 1.0
    for k in intent:
        intent[k] /= total


def _score_actor(actor_key: str) -> dict[str, Any]:
    if actor_key in _scores:
        return _scores[actor_key]
    recent = _events[-500:]

    # The graph carries p_human as a node feature, so it is computed here from
    # the same classifier the decision plane uses. Recomputing it rather than
    # inventing a proxy keeps the two planes from disagreeing about an actor.
    by_actor: dict[str, list[dict[str, Any]]] = {}
    for event in recent:
        key = (event.get("session") or {}).get("actor_key")
        if key:
            by_actor.setdefault(key, []).append(event)
    p_human = {key: classify(evs).p_human for key, evs in by_actor.items()}

    graph = build_graph(recent, p_human=p_human)
    model, scorer = _load_model()
    result = scorer(model, graph, actor_key) if model else _fallback_score(graph, actor_key)

    # Pattern evidence travels with the score so the decision plane can see
    # what the graph model was looking at.
    matched = pattern_score(by_actor.get(actor_key, []))
    result = dict(result)
    result["patterns"] = matched["match_ids"]
    result["pattern_coverage"] = matched["coverage"]
    _scores[actor_key] = result
    return result


def ingest_event(event: dict[str, Any]) -> None:
    _events.append(event)
    if len(_events) > 2000:
        del _events[:500]
    actor = (event.get("session") or {}).get("actor_key")
    if actor:
        _scores.pop(actor, None)


async def handler(req: dict) -> tuple[int, dict[str, str], bytes]:
    path, method = req["path"], req["method"]
    if method == "GET" and path == "/health":
        model, _ = _load_model()
        body = json.dumps(
            {
                "ok": True,
                "events_buffered": len(_events),
                "scores_cached": len(_scores),
                "model": "gnn" if model else "fallback",
                "trained": bool(getattr(model, "trained", False)),
            }
        ).encode()
        return 200, {"Content-Type": "application/json"}, body
    if method == "GET" and path.startswith("/v1/score/"):
        actor_key = path.split("/v1/score/", 1)[1]
        return 200, {"Content-Type": "application/json"}, json.dumps(
            _score_actor(actor_key)
        ).encode()
    if method == "POST" and path == "/v1/events":
        try:
            payload = json_body(req)
        except Exception:
            return 400, {"Content-Type": "text/plain"}, b"invalid json\n"
        events = payload if isinstance(payload, list) else payload.get("events", [])
        for ev in events:
            if isinstance(ev, dict):
                ingest_event(ev)
        return 204, {}, b""
    if method == "POST" and path == "/v1/rescore":
        _scores.clear()
        actors = {
            (e.get("session") or {}).get("actor_key")
            for e in _events
            if (e.get("session") or {}).get("actor_key")
        }
        for actor in actors:
            _score_actor(actor)
        return 200, {"Content-Type": "application/json"}, json.dumps(
            {"rescored": len(actors)}
        ).encode()
    return 404, {"Content-Type": "text/plain"}, b"not found\n"


async def main() -> None:
    import asyncio
    import urllib.request

    async def poll_logger() -> None:
        """Background ingest from logger tail."""
        while True:
            try:
                url = f"http://{LOGGER_HOST}:{LOGGER_PORT}/v1/tail?n=50"
                raw = await asyncio.to_thread(
                    urllib.request.urlopen, url, timeout=3
                )
                data = json.loads(raw.read())
                for line in data.get("lines") or []:
                    ingest_event(line)
            except Exception:
                pass
            await asyncio.sleep(2.0)

    server = await serve(BIND, PORT, handler, name="gnn-scorer")
    poll_task = asyncio.create_task(poll_logger())
    async with server:
        try:
            await server.serve_forever()
        finally:
            poll_task.cancel()


if __name__ == "__main__":
    import asyncio

    asyncio.run(main())
