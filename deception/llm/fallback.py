"""State-constrained LLM fallback for unsupported shell commands.

Contract (PROMPT_FOR_CURSOR.md):
  retrieve virtual FS context (MiniLM) → Qwen 7B generate_response(...)

LLM is NOT the controller. Deterministic commands never enter this path.
"""

from __future__ import annotations

import os
import shlex
from typing import TYPE_CHECKING, Protocol

from deception.llm.rag import retrieve_context
from deception.runtime.host import Session

if TYPE_CHECKING:
    from deception.command_engine.engine import CommandResult


class LlmClient(Protocol):
    def complete(self, system_prompt: str, user_prompt: str) -> str: ...


class MockLlmClient:
    """Deterministic stub — used in tests / offline demos."""

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        hostname = "unknown"
        user = "admin"
        for ln in system_prompt.splitlines():
            if "Host " in ln and " runs " in ln:
                try:
                    hostname = ln.split("Host ", 1)[1].split(" ", 1)[0]
                except IndexError:
                    pass
            if ln.startswith("hostname:"):
                hostname = ln.split(":", 1)[1].strip()
            if ln.startswith("user="):
                user = ln.split("user=", 1)[1].split()[0]

        cmd = ""
        if "Command:" in user_prompt:
            cmd = user_prompt.split("Command:", 1)[1].strip().splitlines()[0].strip()
        elif user_prompt.strip():
            cmd = user_prompt.strip().splitlines()[-1].strip()

        try:
            parts = shlex.split(cmd)
        except ValueError:
            parts = cmd.split()
        name = parts[0] if parts else cmd

        if name in {"nmap", "tcpdump", "masscan", "hydra"}:
            return f"bash: {name}: command not found\n"
        if name in {"uname"}:
            return f"Linux {hostname} 5.15.0-112-generic #122-Ubuntu SMP x86_64 GNU/Linux\n"
        if name in {"hostname"}:
            return f"{hostname}\n"
        if name in {"id"}:
            return f"uid=1000({user}) gid=1000({user}) groups=1000({user})\n"
        if name in {"uptime"}:
            return " 12:04:01 up 3 days,  4:12,  1 user,  load average: 0.08, 0.11, 0.09\n"
        return (
            f"{name}: permission denied\n"
            f"# (llm-mock on {hostname} as {user}; constrained by retrieved evidence)\n"
        )


def _system_prompt(retrieved_context: str) -> str:
    return (
        "You are a deterministic Linux bash shell on ONE virtual host.\n"
        "Stay in character: output ONLY terminal stdout/stderr text.\n"
        "Use ONLY the retrieved virtual filesystem / host evidence below.\n"
        "Do NOT invent hosts, IPs, users, files, routes, or credentials "
        "missing from the evidence.\n"
        "Do NOT mention AI, LLM, RAG, honeypot, or simulation.\n"
        "No markdown fences. No explanations outside shell output.\n"
        "If the binary would not exist on a minimal Ubuntu server, output:\n"
        "bash: <cmd>: command not found\n"
        "\n=== retrieved evidence ===\n"
        f"{retrieved_context}\n"
        "=== end evidence ===\n"
    )


def get_llm_client() -> LlmClient:
    mode = os.environ.get("NETOSIS_LLM_MODE", "mock").lower()
    if mode in {"http", "qwen", "nim", "openai", "ollama"}:
        from deception.llm.openai_client import OpenAICompatibleClient

        return OpenAICompatibleClient()
    return MockLlmClient()


def generate_response(
    session: Session,
    command: str,
    retrieved_context: str | None = None,
    *,
    client: LlmClient | None = None,
) -> CommandResult:
    """Generate shell-like output from Qwen/mock using retrieved virtual FS context."""
    from deception.command_engine.engine import CommandResult

    context = retrieved_context if retrieved_context is not None else retrieve_context(
        session, command
    )
    system = _system_prompt(context)
    user = (
        f"user={session.user} cwd={session.cwd} host={session.host.hostname}\n"
        f"Command:\n{command}"
    )
    llm = client or get_llm_client()
    text = llm.complete(system, user)
    if not text.endswith("\n"):
        text += "\n"
    if text.startswith("```"):
        lines = [ln for ln in text.splitlines() if not ln.strip().startswith("```")]
        text = "\n".join(lines).lstrip("\n")
        if not text.endswith("\n"):
            text += "\n"

    exit_code = 127 if "command not found" in text else 0
    if "permission denied" in text.lower():
        exit_code = 1

    if exit_code == 127:
        return CommandResult(
            stdout="", stderr=text, exit_code=exit_code, command=command, llm_fallback=True
        )
    if exit_code != 0:
        return CommandResult(
            stdout="", stderr=text, exit_code=exit_code, command=command, llm_fallback=True
        )
    return CommandResult(
        stdout=text, stderr="", exit_code=0, command=command, llm_fallback=True
    )


# Compat helpers used by older tests
def build_system_prompt(session: Session, command: str) -> str:
    return _system_prompt(retrieve_context(session, command))
