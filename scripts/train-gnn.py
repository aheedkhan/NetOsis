#!/usr/bin/env python3
"""
Train the actor graph model on the collected corpus.

Targets come from cs.patterns.weak_label — rule matches over event sequences.
The model is therefore a smoothed, generalising version of rules that can be
read and argued with, which is the honest description of what it does. It is
not learning intent from nothing.

Windowing: the corpus is cut into overlapping time windows and a graph is built
for each. An actor appears in several windows with different neighbourhoods, so
the model sees the same actor under varying graph context rather than memorising
one static graph.

Usage:
    python3 scripts/train-gnn.py [--events PATH] [--epochs N] [--out PATH]
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from datetime import datetime

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "lib"))

import torch
import torch.nn.functional as F

from cs.belief import OBJECTIVES
from cs.gnn_model import ActorGNN, N_OBJECTIVES, save
from cs.graph import build_graph
from cs.operator import classify
from cs.patterns import weak_label


def parse_ts(raw):
    if not isinstance(raw, str):
        return None
    for parse in (
        lambda r: datetime.strptime(r, "%Y-%m-%dT%H:%M:%S.%f%z").timestamp(),
        lambda r: datetime.fromisoformat(r.replace("Z", "+00:00")).timestamp(),
    ):
        try:
            return parse(raw)
        except ValueError:
            continue
    return None


def load_events(paths):
    events = []
    for path in paths:
        p = pathlib.Path(path)
        if not p.exists():
            continue
        with p.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    events = [e for e in events if parse_ts(e.get("@timestamp")) is not None]
    events.sort(key=lambda e: parse_ts(e["@timestamp"]))
    return events


def windows(events, span_s, stride_s):
    if not events:
        return
    start = parse_ts(events[0]["@timestamp"])
    end = parse_ts(events[-1]["@timestamp"])
    if end - start < span_s:
        yield events
        return
    cursor = start
    while cursor < end:
        lo, hi = cursor, cursor + span_s
        chunk = [e for e in events if lo <= parse_ts(e["@timestamp"]) < hi]
        if len(chunk) >= 5:
            yield chunk
        cursor += stride_s


def build_examples(events, span_s, stride_s):
    """One example per (window, actor with a usable weak label)."""
    examples = []
    for chunk in windows(events, span_s, stride_s):
        by_actor = {}
        for event in chunk:
            key = (event.get("session") or {}).get("actor_key")
            if key:
                by_actor.setdefault(key, []).append(event)

        p_human = {
            key: classify(evs).p_human for key, evs in by_actor.items()
        }
        graph = build_graph(chunk, p_human=p_human)
        keys = graph["node_keys"]

        targets = {}
        for key, evs in by_actor.items():
            label = weak_label(evs)
            if label is not None and key in keys:
                targets[keys.index(key)] = label
        if targets:
            examples.append((graph, targets))
    return examples


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--events", nargs="*", default=["data/events/events.jsonl"])
    ap.add_argument("--epochs", type=int, default=300)
    ap.add_argument("--lr", type=float, default=0.01)
    ap.add_argument("--window", type=float, default=900.0)
    ap.add_argument("--stride", type=float, default=300.0)
    ap.add_argument("--out", default="data/models/actor-gnn.pt")
    args = ap.parse_args()

    events = load_events(args.events)
    print(f"loaded {len(events)} events from {len(args.events)} source(s)")
    if not events:
        print("no events — nothing to train on", file=sys.stderr)
        return 1

    examples = build_examples(events, args.window, args.stride)
    labelled = sum(len(t) for _, t in examples)
    print(f"built {len(examples)} graph window(s), {labelled} labelled actor-instance(s)")
    if labelled < 4:
        print(
            "not enough rule-labelled actors to train. Run more traffic through "
            "the lab first (./cs redteam, ./cs attacker) and try again.",
            file=sys.stderr,
        )
        return 2

    model = ActorGNN()
    model.train()
    optimiser = torch.optim.Adam(model.parameters(), lr=args.lr)

    objective_index = {name: i for i, name in enumerate(OBJECTIVES)}

    for epoch in range(1, args.epochs + 1):
        total = 0.0
        for graph, targets in examples:
            x = torch.tensor(graph["node_features"], dtype=torch.float32)
            ei = torch.tensor(graph["edge_index"], dtype=torch.long)
            if ei.numel() == 0:
                ei = torch.zeros((2, 0), dtype=torch.long)

            out = model(x, ei)
            loss = torch.zeros(())
            for node_index, label in targets.items():
                vector = out[node_index]

                # Intent: cross-entropy against the rule mixture.
                target_intent = torch.tensor(
                    [label["intent"].get(o, 0.0) for o in OBJECTIVES],
                    dtype=torch.float32,
                )
                target_intent = target_intent / target_intent.sum().clamp(min=1e-6)
                log_p = F.log_softmax(vector[3 : 3 + N_OBJECTIVES], dim=0)
                loss = loss - (target_intent * log_p).sum()

                # Scalars: the rules give a point estimate, weighted by how much
                # rule evidence stood behind it.
                weight = float(label["coverage"])
                loss = loss + weight * F.mse_loss(
                    torch.sigmoid(vector[0]),
                    torch.tensor(float(label["intel_gain"])),
                )
                loss = loss + weight * F.mse_loss(
                    torch.sigmoid(vector[1]),
                    torch.tensor(float(label["suspicion"])),
                )

            optimiser.zero_grad()
            loss.backward()
            optimiser.step()
            total += float(loss.detach())

        if epoch % 50 == 0 or epoch == 1:
            print(f"  epoch {epoch:4d}  loss {total / max(len(examples),1):.4f}")

    model.eval()
    model.trained = True
    path = save(model, pathlib.Path(args.out))
    print(f"saved trained checkpoint to {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
