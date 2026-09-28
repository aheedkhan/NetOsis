"""Multi-hacker RAG profiles stay isolated per actor_id."""

from __future__ import annotations

import os
import tempfile
import uuid
from pathlib import Path

from attack_graph.model.graph import AttackGraph
from deception.llm.rag import retrieve_context
from deception.runtime.host import Session, VirtualHost
from deception.runtime.pipeline import VerticalSlicePipeline
from deception.runtime.profile_store import ProfileStore
from rag.ingest import build_corpus
from telemetry.storage.jsonl import JsonlTelemetryStore

ROOT = Path(__file__).resolve().parents[2]
HOST = ROOT / "deception" / "hosts" / "enterprise-web.yml"


def test_two_hackers_have_separate_rag_profiles() -> None:
    os.environ["NETOSIS_EMBED_MODE"] = "hash"
    os.environ["NETOSIS_RAG_MULTI_ACTOR"] = "1"

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        os.environ["NETOSIS_DATA_DIR"] = str(tmp_path)
        store_a = JsonlTelemetryStore(tmp_path / "a.jsonl")
        store_b = JsonlTelemetryStore(tmp_path / "b.jsonl")
        profiles = ProfileStore(tmp_path / "profiles")

        host_a = VirtualHost.load(HOST)
        host_b = VirtualHost.load(HOST)
        sess_a = Session(
            host=host_a,
            session_id=str(uuid.uuid4()),
            actor_id="actor-10.0.0.1",
            source_ip="10.0.0.1",
        )
        sess_b = Session(
            host=host_b,
            session_id=str(uuid.uuid4()),
            actor_id="actor-10.0.0.2",
            source_ip="10.0.0.2",
        )

        pipe_a = VerticalSlicePipeline(
            session=sess_a, store=store_a, graph=AttackGraph(), profile_store=profiles
        )
        pipe_b = VerticalSlicePipeline(
            session=sess_b, store=store_b, graph=AttackGraph(), profile_store=profiles
        )

        pipe_a.run_command("mkdir hacker_a_loot")
        pipe_a.run_command("echo alpha > hacker_a_loot/a.txt")
        pipe_a.run_command("apt install hydra")

        pipe_b.run_command("mkdir hacker_b_tools")
        pipe_b.run_command("echo beta > hacker_b_tools/b.txt")
        pipe_b.run_command("apt install nmap")

        # Refresh other-actor docs after both saved
        pipe_a._refresh_profile_rag_docs()
        pipe_b._refresh_profile_rag_docs()

        docs_a = build_corpus(sess_a)
        docs_b = build_corpus(sess_b)
        text_a = "\n".join(d.text for d in docs_a)
        text_b = "\n".join(d.text for d in docs_b)

        assert "hacker_a_loot" in text_a
        assert "hydra" in text_a
        assert "CURRENT ATTACKER" in text_a or "actor-10.0.0.1" in text_a

        assert "hacker_b_tools" in text_b
        assert "nmap" in text_b

        # A's live FS must not contain B's dirs
        assert "/home/admin/hacker_b_tools" not in sess_a.host.filesystem
        assert "/home/admin/hacker_a_loot" not in sess_b.host.filesystem

        # RAG for A pins A's profile; other attacker labeled separately
        ctx_a = retrieve_context(sess_a, "what did I create")
        assert "hacker_a_loot" in ctx_a or "actor-10.0.0.1" in ctx_a
        assert "OTHER attacker" in ctx_a or "actor-10.0.0.2" in text_a

        # Profile files on disk
        assert (tmp_path / "profiles" / "actor-10.0.0.1.json").is_file()
        assert (tmp_path / "profiles" / "actor-10.0.0.2.json").is_file()
        pa = profiles.load("actor-10.0.0.1")
        pb = profiles.load("actor-10.0.0.2")
        assert "hydra" in pa.packages_attempted
        assert "nmap" in pb.packages_attempted
        assert "hydra" not in pb.packages_attempted
