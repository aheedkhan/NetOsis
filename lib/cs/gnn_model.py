"""
Graph model over the actor graph.

Why a graph at all. The per-actor signals — timing, pattern matches, engagement
depth — are computed from one actor's own events. But actors are not
independent: two addresses sharing a rare client fingerprint, hitting the same
published service in the same hour, are evidence about each other. A model that
passes messages along those edges can reach a conclusion about a quiet actor
from the behaviour of a noisy one it is connected to, which no per-actor feature
can do.

Why it is trained on rules. There is no labelled corpus of adversary intent for
a honeypot that has not been deployed, so the targets come from
cs.patterns.weak_label — transparent, auditable rules that fire on sequences.
The model is then a smoothed, generalising version of those rules rather than an
oracle, and that is exactly how it should be described: it earns its place by
propagating rule-derived evidence across the graph, not by knowing something the
rules do not.

Why an untrained model must not score. The previous version constructed a fresh
randomly-initialised network whenever no checkpoint was present and passed its
output through a sigmoid. That produces confident-looking numbers around 0.5-0.9
that mean nothing, and because the decision plane merged suspicion with max(),
the noise could only ever push actors toward BURN. An untrained model here
returns explicit priors and says so in the `model` field, so a caller can tell
the difference between a score and a placeholder.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import torch
import torch.nn as nn
import torch.nn.functional as F

from cs.belief import OBJECTIVES, default_intent

IN_DIM = 12  # keep in step with cs.graph.FEATURE_NAMES
HIDDEN = 32
N_OBJECTIVES = len(OBJECTIVES)
OUT_DIM = 3 + N_OBJECTIVES  # intel_gain, suspicion, novelty, then intent logits

CHECKPOINT = Path(os.environ.get("CS_GNN_CHECKPOINT", "/data/models/actor-gnn.pt"))
SEED = int(os.environ.get("CS_GNN_SEED", "1337"))


class ActorGNN(nn.Module):
    """Two-layer graph convolution with symmetric neighbour normalisation."""

    def __init__(self) -> None:
        super().__init__()
        # Deterministic initialisation so an untrained model is at least
        # reproducible, and so two replicas of the scorer agree.
        generator = torch.Generator().manual_seed(SEED)
        self.lin1 = nn.Linear(IN_DIM, HIDDEN)
        self.lin2 = nn.Linear(HIDDEN, HIDDEN)
        self.head = nn.Linear(HIDDEN, OUT_DIM)
        for layer in (self.lin1, self.lin2, self.head):
            nn.init.xavier_uniform_(layer.weight, generator=generator)
            nn.init.zeros_(layer.bias)
        # Set to True only by the trainer. Nothing else may flip it.
        self.trained: bool = False

    @staticmethod
    def _propagate(x: torch.Tensor, edge_index: torch.Tensor) -> torch.Tensor:
        """Mean of each node's neighbours, added to the node's own features."""
        if edge_index.numel() == 0:
            return x
        row, col = edge_index
        degree = torch.zeros(x.size(0), device=x.device).scatter_add_(
            0, row, torch.ones(row.size(0), device=x.device)
        ).clamp(min=1.0)
        aggregate = torch.zeros_like(x)
        aggregate.scatter_add_(0, row.unsqueeze(1).expand(-1, x.size(1)), x[col])
        return x + aggregate / degree.unsqueeze(1)

    def forward(self, x: torch.Tensor, edge_index: torch.Tensor) -> torch.Tensor:
        h = F.relu(self.lin1(self._propagate(x, edge_index)))
        h = F.relu(self.lin2(self._propagate(h, edge_index)))
        return self.head(h)


# --------------------------------------------------------------------------
# Checkpointing
# --------------------------------------------------------------------------

def save(model: ActorGNN, path: Path | None = None) -> Path:
    target = Path(path or CHECKPOINT)
    target.parent.mkdir(parents=True, exist_ok=True)
    torch.save(
        {
            "state_dict": model.state_dict(),
            "trained": True,
            "in_dim": IN_DIM,
            "objectives": list(OBJECTIVES),
        },
        target,
    )
    return target


def load(path: Path | None = None) -> ActorGNN:
    """
    Load a checkpoint if one exists. A model returned without a checkpoint is
    explicitly untrained and will not be allowed to produce scores.
    """
    model = ActorGNN()
    source = Path(path or CHECKPOINT)
    if not source.exists():
        model.eval()
        return model
    try:
        blob = torch.load(source, map_location="cpu", weights_only=False)
        if list(blob.get("objectives") or OBJECTIVES) != list(OBJECTIVES):
            # The objective taxonomy changed under the checkpoint. Refusing is
            # correct: the intent head's outputs would silently mean something
            # different from what the caller expects.
            print(
                "GNN checkpoint objective taxonomy does not match; ignoring it",
                flush=True,
            )
            model.eval()
            return model
        model.load_state_dict(blob["state_dict"])
        model.trained = bool(blob.get("trained", False))
    except Exception as exc:
        print(f"GNN checkpoint unreadable ({exc}); continuing untrained", flush=True)
    model.eval()
    return model


# --------------------------------------------------------------------------
# Scoring
# --------------------------------------------------------------------------

def _prior_score(actor_key: str, reason: str) -> dict[str, Any]:
    """
    What to return when the model cannot legitimately be asked.

    These are neutral priors, not predictions: intelligence gain low, suspicion
    at the same baseline the belief state starts from, novelty high because an
    unseen actor genuinely is novel, and a flat intent distribution. The `model`
    field names the reason so a caller never mistakes this for a score.
    """
    return {
        "actor_key": actor_key,
        "intel_gain": 0.2,
        "suspicion": 0.05,
        "novelty": 1.0,
        "intent": default_intent(),
        "model": reason,
        "trained": False,
    }


def score_graph(
    model: ActorGNN | None,
    graph: dict[str, Any],
    actor_key: str,
) -> dict[str, Any]:
    if not graph.get("node_features"):
        return _prior_score(actor_key, "gnn-empty-graph")

    if model is None or not getattr(model, "trained", False):
        return _prior_score(actor_key, "gnn-untrained")

    keys = graph.get("node_keys") or []
    if actor_key not in keys:
        return _prior_score(actor_key, "gnn-actor-absent")

    x = torch.tensor(graph["node_features"], dtype=torch.float32)
    edge_index = torch.tensor(graph["edge_index"], dtype=torch.long)
    if edge_index.numel() == 0:
        edge_index = torch.zeros((2, 0), dtype=torch.long)

    with torch.no_grad():
        out = model(x, edge_index)

    vector = out[keys.index(actor_key)]
    # Softmax over the intent head, not a normalised raw sum. The earlier
    # version divided the raw logits by their sum, which produced values above
    # one and below zero whenever the logits had mixed signs — the observed
    # symptom was an "intent distribution" containing 1.81.
    intent_probabilities = torch.softmax(vector[3 : 3 + N_OBJECTIVES], dim=0)

    return {
        "actor_key": actor_key,
        "intel_gain": float(torch.sigmoid(vector[0])),
        "suspicion": float(torch.sigmoid(vector[1])),
        "novelty": float(torch.sigmoid(vector[2])),
        "intent": {
            objective: float(intent_probabilities[i])
            for i, objective in enumerate(OBJECTIVES)
        },
        "model": "gnn-trained",
        "trained": True,
    }
