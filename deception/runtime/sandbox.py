"""Sandbox client for external fetch/run — Phase 1 in-process mock.

Phase 2: set NETOSIS_SANDBOX_URL to SOC API (192.168.40.31:8000); same interface.
Real code never runs on the low-level HHP; attacker only sees sanitized stdout.
"""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol
from urllib.parse import urlparse

import yaml

from deception.runtime.host import Session

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MALWARE_LIST = ROOT / "deception" / "lore" / "malware_ips.yml"


@dataclass
class SandboxResult:
    stdout: str
    stderr: str = ""
    exit_code: int = 0
    contained: bool = False
    classification: str = "utility"  # malware | gray | utility
    job_id: str = ""
    files_created: list[dict[str, str]] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    sample_sha256: str | None = None


class SandboxClient(Protocol):
    def run(self, session: Session, command: str) -> SandboxResult: ...


def _load_malware_ips(path: Path | None = None) -> set[str]:
    p = path or Path(os.environ.get("NETOSIS_MALWARE_IPS", str(DEFAULT_MALWARE_LIST)))
    if not p.is_file():
        return {"185.220.101.1", "malware.example", "evil.onion"}
    raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    hosts: set[str] = set()
    for item in raw.get("blocked_hosts") or []:
        hosts.add(str(item).lower().strip())
    for item in raw.get("blocked_ips") or []:
        hosts.add(str(item).lower().strip())
    return hosts


_URL_RE = re.compile(r"https?://[^\s\"']+", re.I)


def extract_external_targets(command: str) -> list[str]:
    """Return external URLs/hosts (not RFC1918 / localhost)."""
    found: list[str] = []
    for m in _URL_RE.finditer(command):
        found.append(m.group(0))
    # bare host after git clone
    parts = command.split()
    for i, p in enumerate(parts):
        if p == "clone" and i + 1 < len(parts) and "://" not in parts[i + 1]:
            # git@github.com:org/repo.git
            found.append(parts[i + 1])
    out: list[str] = []
    for item in found:
        host = item
        if "://" in item:
            host = urlparse(item).hostname or item
        elif "@" in item and ":" in item:
            # git@host:path
            host = item.split("@", 1)[1].split(":", 1)[0]
        host = (host or "").lower().rstrip(".")
        if not host or _is_lab_or_local(host):
            continue
        out.append(item if ("://" in item or "@" in item) else host)
    return out


def _is_lab_or_local(host: str) -> bool:
    if host in {"localhost", "127.0.0.1", "::1"}:
        return True
    if re.match(r"^192\.168\.\d+\.\d+$", host):
        return True
    if re.match(r"^10\.\d+\.\d+\.\d+$", host):
        return True
    if re.match(r"^172\.(1[6-9]|2\d|3[0-1])\.\d+\.\d+$", host):
        return True
    if host.endswith(".corp.local") or host.endswith(".internal"):
        return True
    return False


def should_sandbox(command: str) -> bool:
    """True if command should leave the HHP for sandbox (external or ./ payload)."""
    line = command.strip()
    if not line:
        return False
    parts = line.split()
    cmd = parts[0]
    if cmd in {"curl", "wget"}:
        return bool(extract_external_targets(line))
    if cmd == "git" and len(parts) > 1 and parts[1] == "clone":
        return True
    if cmd.startswith("./") or (
        cmd.startswith("/")
        and any(cmd.startswith(p) for p in ("/tmp/", "/home/", "/var/tmp/"))
    ):
        return True
    if cmd in {"python", "python3", "bash", "sh"} and any(
        a.endswith((".py", ".sh", ".elf", ".bin")) for a in parts[1:]
    ):
        return True
    return False


def sanitize_sandbox_output(text: str) -> str:
    """Never leak pod/k8s/API internals to the attacker shell."""
    if not text:
        return text
    out = text
    for pat, repl in (
        (r"(?i)kubernetes|k3s|\bk8s\b|pod/|namespace|netosis-sandbox", "process"),
        (r"(?i)192\.168\.40\.31:8000|NETOSIS_SANDBOX|SandboxClient", "localhost"),
        (r"(?i)Traceback \(most recent call last\):[\s\S]*", "error: command failed\n"),
    ):
        out = re.sub(pat, repl, out)
    return out


def _ensure_parents(session: Session, path: str) -> None:
    parts = [x for x in path.split("/") if x]
    cur = ""
    for part in parts[:-1]:
        cur = f"{cur}/{part}"
        if cur not in session.host.filesystem:
            session.host.filesystem[cur] = {"type": "dir"}
            session.note_created(cur)


class MockSandboxClient:
    """In-process Phase-1 sandbox — forges curl/git, contains bad IPs, updates session FS."""

    def __init__(self, malware_hosts: set[str] | None = None) -> None:
        self.malware_hosts = (
            malware_hosts if malware_hosts is not None else _load_malware_ips()
        )

    def run(self, session: Session, command: str) -> SandboxResult:
        urls = extract_external_targets(command)
        job_id = hashlib.sha256(f"{session.actor_id}:{command}".encode()).hexdigest()[:12]

        for u in urls:
            host = urlparse(u).hostname if "://" in u else u
            if "@" in (host or "") and ":" in u:
                host = u.split("@", 1)[1].split(":", 1)[0]
            host = (host or u).lower()
            if host in self.malware_hosts or any(
                blocked in host for blocked in self.malware_hosts
            ):
                sample = hashlib.sha256(command.encode()).hexdigest()
                stdout = sanitize_sandbox_output(
                    f"curl: (7) Failed to connect to {host} port 443: Connection timed out\n"
                )
                result = SandboxResult(
                    stdout=stdout,
                    exit_code=7,
                    contained=True,
                    classification="malware",
                    job_id=job_id,
                    urls=urls,
                    sample_sha256=sample,
                )
                self._record_job(session, command, result)
                return result

        files: list[dict[str, str]] = []
        parts = command.strip().split()
        cmd = parts[0] if parts else ""
        classification = "utility"
        sample: str | None = None

        if cmd in {"curl", "wget"}:
            stdout, files = self._forge_curl(session, command, urls)
        elif cmd == "git":
            stdout, files = self._forge_git(session, command, urls)
        elif cmd.startswith("./") or cmd.startswith("/"):
            name = Path(cmd.split()[0]).name
            stdout = f"Running {name}...\n{name}: done (exit 0)\n"
            classification = "gray"
            sample = hashlib.sha256(command.encode()).hexdigest()
        else:
            stdout = f"{command}\nOK\n"
            classification = "gray"
            sample = hashlib.sha256(command.encode()).hexdigest()

        for f in files:
            path = f["path"]
            content = f.get("content", "")
            _ensure_parents(session, path)
            session.host.filesystem[path] = {"type": "file", "content": content}
            session.note_created(path)

        result = SandboxResult(
            stdout=sanitize_sandbox_output(stdout),
            exit_code=0,
            contained=False,
            classification=classification,
            job_id=job_id,
            files_created=files,
            urls=urls,
            sample_sha256=sample,
        )
        self._record_job(session, command, result)
        return result

    def _record_job(self, session: Session, command: str, result: SandboxResult) -> None:
        session.sandbox_jobs.append(
            {
                "job_id": result.job_id,
                "command": command,
                "classification": result.classification,
                "contained": result.contained,
                "urls": list(result.urls),
                "files": [f["path"] for f in result.files_created],
                "sample_sha256": result.sample_sha256,
            }
        )

    def _forge_curl(
        self, session: Session, command: str, urls: list[str]
    ) -> tuple[str, list[dict[str, str]]]:
        files: list[dict[str, str]] = []
        url = urls[0] if urls else "https://example.com/"
        out_path = None
        parts = command.split()
        for i, p in enumerate(parts):
            if p in {"-o", "--output"} and i + 1 < len(parts):
                out_path = parts[i + 1]
            if p == "-O":
                out_path = Path(urlparse(url).path or "index.html").name or "download"
        body = (
            f"# fetched for actor {session.actor_id}\n"
            f"# url: {url}\n"
            "OK\n"
        )
        if out_path:
            if out_path.startswith("/"):
                path = out_path
            elif out_path.startswith("./"):
                path = f"{session.cwd.rstrip('/')}/{out_path[2:]}"
            else:
                path = f"{session.cwd.rstrip('/')}/{out_path}"
            files.append({"path": path, "content": body})
            return (
                "  % Total    % Received % Xferd  Average Speed   Time\n"
                f"100  {len(body)}  100  {len(body)}    0     0   9999      0 "
                "--:--:-- --:--:-- --:--:--  9999\n",
                files,
            )
        if "-I" in parts or "-I" in command:
            return ("HTTP/1.1 200 OK\nServer: nginx\n\n", files)
        return (body, files)

    def _forge_git(
        self, session: Session, command: str, urls: list[str]
    ) -> tuple[str, list[dict[str, str]]]:
        files: list[dict[str, str]] = []
        parts = command.split()
        if len(parts) >= 3:
            url = parts[2]
            dest = parts[3] if len(parts) > 3 else (Path(urlparse(url).path).stem or "repo")
        else:
            url = urls[0] if urls else "https://github.com/example/repo.git"
            dest = Path(urlparse(url).path).stem or "repo"
        if dest.startswith("/"):
            base = dest
        else:
            base = f"{session.cwd.rstrip('/')}/{dest}"
        session.host.filesystem[base] = {"type": "dir"}
        session.note_created(base)
        session.host.filesystem[f"{base}/.git"] = {"type": "dir"}
        session.note_created(f"{base}/.git")
        readme = f"# {Path(base).name}\nCloned for actor {session.actor_id}\nsource: {url}\n"
        files.append({"path": f"{base}/README.md", "content": readme})
        files.append(
            {
                "path": f"{base}/.git/config",
                "content": f'[remote "origin"]\n\turl = {url}\n',
            }
        )
        stdout = (
            f"Cloning into '{Path(base).name}'...\n"
            "remote: Enumerating objects: 3, done.\n"
            "Receiving objects: 100% (3/3), done.\n"
        )
        return stdout, files


class HttpSandboxClient:
    """Phase-2 client — POST to SOC sandbox API. Falls back to mock on failure."""

    def __init__(self, base_url: str) -> None:
        self.base_url = base_url.rstrip("/")
        self._mock = MockSandboxClient()

    def run(self, session: Session, command: str) -> SandboxResult:
        try:
            import json
            import urllib.request

            payload = json.dumps(
                {
                    "actor_id": session.actor_id,
                    "command": command,
                    "cwd": session.cwd,
                }
            ).encode()
            req = urllib.request.Request(
                f"{self.base_url}/v1/sandbox/run",
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode())
            result = SandboxResult(
                stdout=sanitize_sandbox_output(str(data.get("stdout", ""))),
                stderr=sanitize_sandbox_output(str(data.get("stderr", ""))),
                exit_code=int(data.get("exit_code", 0)),
                contained=bool(data.get("contained")),
                classification=str(data.get("classification", "utility")),
                job_id=str(data.get("job_id", "")),
                files_created=list(data.get("files_created") or []),
                urls=list(data.get("urls") or []),
                sample_sha256=data.get("sample_sha256"),
            )
            for f in result.files_created:
                path = f.get("path")
                if not path:
                    continue
                _ensure_parents(session, path)
                session.host.filesystem[path] = {
                    "type": "file",
                    "content": f.get("content", ""),
                }
                session.note_created(path)
            self._mock._record_job(session, command, result)
            return result
        except Exception:
            return self._mock.run(session, command)


def get_sandbox_client() -> SandboxClient:
    url = os.environ.get("NETOSIS_SANDBOX_URL", "").strip()
    if url:
        return HttpSandboxClient(url)
    return MockSandboxClient()
