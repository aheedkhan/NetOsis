"""
Actor graph construction.

Nodes are actors and the artefacts that connect them — addresses, client
fingerprints, and the published services they touched. Edges record those
relationships so a graph model can move evidence between actors that share
something, which is the only thing a graph buys over per-actor features.

The node feature vector is the part that matters most. An earlier version
carried six values, four of which were one-hot node-kind flags, so the model had
almost nothing behavioural to learn from and message passing had nothing to
propagate. The features below are the same quantities the rest of the decision
plane reasons about — how machine-like the timing is, how much of the traffic
was refused at the perimeter, how much of it was genuine protocol interaction —
so the model is smoothing evidence the system already trusts rather than
inventing its own.
"""

from __future__ import annotations

import statistics
from datetime import datetime
from typing import Any

EDGE_LINK = 0      # actor <-> fingerprint
EDGE_SESSION = 1   # actor <-> actor, same session
EDGE_IP = 2        # actor <-> address
EDGE_TARGET = 3    # actor <-> published service

# Keep in step with cs.gnn_model.IN_DIM.
FEATURE_NAMES = (
    "events_scaled",
    "dataset_breadth",
    "is_actor",
    "has_hassh",
    "has_ja4",
    "is_artefact",
    "p_human",
    "refused_fraction",
    "interactive_fraction",
    "port_breadth",
    "zone_breadth",
    "burstiness",
)
IN_DIM = len(FEATURE_NAMES)

INTERACTIVE_DATASETS = frozenset(
    {
        "cybersnare.ssh.auth",
        "cybersnare.shell.command",
        "cybersnare.http.request",
        "cybersnare.shell.proc_read",
        "cybersnare.shell.vm_check",
        "cybersnare.sinkhole.http",
    }
)
REFUSED_DATASETS = frozenset(
    {
        "cybersnare.fw.drop",
        "cybersnare.fw.lateral_denied",
        "cybersnare.fw.containment",
    }
)


def _ts(event: dict[str, Any]) -> float | None:
    raw = event.get("@timestamp")
    if not isinstance(raw, str):
        return None
    try:
        return datetime.strptime(raw, "%Y-%m-%dT%H:%M:%S.%f%z").timestamp()
    except ValueError:
        pass
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def _burstiness(stamps: list[float]) -> float:
    """
    How tightly packed this node's events are, on 0..1.

    Sub-second spacing approaches 1 and human-scale spacing approaches 0, so it
    carries the same information as the operator classifier's timing signals in
    a form the network can consume directly.
    """
    if len(stamps) < 2:
        return 0.0
    stamps = sorted(stamps)
    gaps = [b - a for a, b in zip(stamps, stamps[1:]) if b - a >= 0]
    gaps = [g for g in gaps if g < 600]
    if not gaps:
        return 0.0
    median = statistics.median(gaps)
    return float(1.0 / (1.0 + median))


def build_graph(
    events: list[dict[str, Any]],
    *,
    p_human: dict[str, float] | None = None,
) -> dict[str, Any]:
    """
    Build a graph from recent canonical events.

    `p_human` optionally supplies the operator classifier's output per actor
    key. It is passed in rather than recomputed so that the scorer and the
    decision plane cannot disagree about the same actor.
    """
    p_human = p_human or {}
    nodes: dict[str, int] = {}
    node_meta: list[dict[str, Any]] = []
    edges: list[tuple[int, int, int]] = []
    session_actors: dict[str, str] = {}

    def add_node(key: str, meta: dict[str, Any]) -> int:
        if key not in nodes:
            nodes[key] = len(node_meta)
            node_meta.append(
                {
                    "key": key,
                    "events": 0,
                    "datasets": set(),
                    "ports": set(),
                    "zones": set(),
                    "stamps": [],
                    "refused": 0,
                    "interactive": 0,
                    **meta,
                }
            )
        return nodes[key]

    for event in events:
        actor = (event.get("session") or {}).get("actor_key") or "actor:unknown"
        source = event.get("source") or {}
        network = event.get("network") or {}
        destination = event.get("destination") or {}
        firewall = event.get("firewall") or {}

        src_ip = source.get("ip")
        hassh = network.get("hassh")
        ja4 = network.get("ja4")
        dataset = (event.get("event") or {}).get("dataset") or ""
        session_id = (event.get("session") or {}).get("id")

        index = add_node(actor, {"kind": "actor", "hassh": hassh, "ja4": ja4})
        meta = node_meta[index]
        meta["events"] += 1
        if dataset:
            meta["datasets"].add(dataset)
            if dataset in REFUSED_DATASETS:
                meta["refused"] += 1
            if dataset in INTERACTIVE_DATASETS:
                meta["interactive"] += 1
        if isinstance(destination.get("port"), int):
            meta["ports"].add(destination["port"])
        if firewall.get("destination_zone"):
            meta["zones"].add(firewall["destination_zone"])
        stamp = _ts(event)
        if stamp is not None:
            meta["stamps"].append(stamp)
        if hassh and not meta.get("hassh"):
            meta["hassh"] = hassh
        if ja4 and not meta.get("ja4"):
            meta["ja4"] = ja4

        if src_ip:
            ip_index = add_node(f"ip:{src_ip}", {"kind": "ip", "ip": src_ip})
            edges.append((index, ip_index, EDGE_IP))
            edges.append((ip_index, index, EDGE_IP))

        if hassh:
            fp_index = add_node(f"hassh:{hassh}", {"kind": "hassh"})
            edges.append((index, fp_index, EDGE_LINK))
            edges.append((fp_index, index, EDGE_LINK))

        if ja4:
            fp_index = add_node(f"ja4:{ja4}", {"kind": "ja4"})
            edges.append((index, fp_index, EDGE_LINK))
            edges.append((fp_index, index, EDGE_LINK))

        # Two actors that touched the same published service are connected
        # through it. This is the edge that lets the model relate a quiet actor
        # to a noisy one attacking the same thing.
        service = destination.get("service") or (
            f"{destination.get('ip')}:{destination.get('port')}"
            if destination.get("ip")
            else None
        )
        if service:
            svc_index = add_node(f"svc:{service}", {"kind": "service"})
            edges.append((index, svc_index, EDGE_TARGET))
            edges.append((svc_index, index, EDGE_TARGET))

        if session_id:
            previous = session_actors.get(session_id)
            if previous and previous in nodes:
                edges.append((nodes[previous], index, EDGE_SESSION))
            session_actors[session_id] = actor

    features: list[list[float]] = []
    for meta in node_meta:
        count = float(meta.get("events") or 0)
        is_actor = 1.0 if meta.get("kind") == "actor" else 0.0
        features.append(
            [
                min(1.0, count / 50.0),
                min(1.0, len(meta["datasets"]) / 10.0),
                is_actor,
                1.0 if meta.get("hassh") else 0.0,
                1.0 if meta.get("ja4") else 0.0,
                0.0 if is_actor else 1.0,
                float(p_human.get(meta["key"], 0.5)),
                (meta["refused"] / count) if count else 0.0,
                (meta["interactive"] / count) if count else 0.0,
                min(1.0, len(meta["ports"]) / 20.0),
                min(1.0, len(meta["zones"]) / 5.0),
                _burstiness(meta["stamps"]),
            ]
        )

    edge_index: list[list[int]] = [[], []]
    edge_attr: list[int] = []
    for src, dst, etype in edges:
        edge_index[0].append(src)
        edge_index[1].append(dst)
        edge_attr.append(etype)

    for meta in node_meta:
        meta["datasets"] = sorted(meta["datasets"])
        meta["ports"] = sorted(meta["ports"])
        meta["zones"] = sorted(meta["zones"])
        meta.pop("stamps", None)

    return {
        "num_nodes": len(node_meta),
        "num_edges": len(edge_attr),
        "node_keys": [m["key"] for m in node_meta],
        "node_features": features,
        "feature_names": list(FEATURE_NAMES),
        "edge_index": edge_index,
        "edge_attr": edge_attr,
        "nodes": node_meta,
    }
