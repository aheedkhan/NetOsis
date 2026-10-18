"""The RAG corpus is read by the LLM while it answers attackers.

Nothing in it may reveal the trap (honeypot/decoy/lore wording), the lab
platform (Proxmox, OPNsense, Kali, the management network) or any real,
non-honeypot server address. See deception/lore/topology.yml for the rule.
"""

from __future__ import annotations

import re

from rag.ingest import load_static_corpus

FORBIDDEN = re.compile(
    r"\b(honeypot|decoy|hhp|kali|proxmox|opnsense|paramiko|pfsense|fyp|viva|llm|rag|lore|theater|"
    r"fake|synthetic|deception|simulat\w*|jump ?box|vpn|freerdp)\b|\bhp\b|172\.30\.",
    re.I,
)
# Real (non-honeypot) assets and the SOC must never be offered to an attacker.
REAL_ASSETS = ("192.168.30.31", "192.168.30.40", "192.168.10.50", "192.168.20.50", "192.168.40.")


def test_corpus_has_no_out_of_character_or_real_infra_text() -> None:
    docs = load_static_corpus()
    assert docs, "corpus should load"
    for doc in docs:
        hit = FORBIDDEN.search(doc.text)
        assert hit is None, f"{doc.doc_id}: reveals the deception/lab: {hit.group(0)!r}"
        for ip in REAL_ASSETS:
            assert ip not in doc.text, f"{doc.doc_id}: lists real asset {ip}"


def test_full_llm_context_for_every_host_is_clean() -> None:
    """Everything build_corpus() feeds the model: host facts, files, segments, corpus."""
    from pathlib import Path

    from deception.runtime.host import Session, VirtualHost
    from rag.ingest import build_corpus

    hosts = Path(__file__).resolve().parents[2] / "deception" / "hosts"
    for host_file in sorted(hosts.glob("*.yml")):
        host = VirtualHost.load(host_file)
        session = Session(host=host, session_id="t", actor_id="actor-203.0.113.9",
                          source_ip="203.0.113.9", user="admin")
        for doc in build_corpus(session):
            hit = FORBIDDEN.search(doc.text)
            assert hit is None, f"{host_file.name}/{doc.doc_id}: {hit.group(0)!r}"
            for ip in REAL_ASSETS:
                assert ip not in doc.text, f"{host_file.name}/{doc.doc_id}: real asset {ip}"
