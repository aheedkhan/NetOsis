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
            from deception.llm.fake_shell import parse_nmap_target

            target = parse_nmap_target(cmd) or "127.0.0.1"
            return (
                "Starting Nmap 7.80 ( https://nmap.org ) at 2024-06-12 14:22 UTC\n"
                f"Nmap scan report for {target}\n"
                "Host is up (0.00042s latency).\n"
                "PORT   STATE SERVICE VERSION\n"
                "22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10\n"
                "80/tcp open  http    nginx 1.18.0\n"
                "Nmap done: 1 IP address (1 host up) scanned in 1.84 seconds\n"
            )
        if name in {"apt", "apt-get"}:
            from deception.llm.fake_shell import apt_already_newest

            pkgs = [p for p in parts[2:] if not p.startswith("-")] if len(parts) > 1 else ["nmap"]
            return apt_already_newest(pkgs or ["nmap"])
        if name in {"mkdir", "touch", "rm", "rmdir"}:
            return ""
        if name == "echo":
            return ""
        if name in {"sudo", "su"}:
            return ""
        if name in {"id"}:
            return f"uid=1000({user}) gid=1000({user}) groups=1000({user}),27(sudo)\n"
        if name in {"uname"}:
            return f"Linux {hostname} 5.15.0-112-generic #122-Ubuntu SMP x86_64 GNU/Linux\n"
        if name in {"hostname"}:
            return f"{hostname}\n"
        if name in {"uptime"}:
            return " 12:04:01 up 3 days,  4:12,  1 user,  load average: 0.08, 0.11, 0.09\n"
        return (
            f"bash: {name}: command not found\n"
        )


def _system_prompt(retrieved_context: str) -> str:
    return (
        "You are a realistic Ubuntu 22.04 bash shell on ONE virtual host.\n"
        "Output ONLY terminal stdout/stderr text. No markdown. No explanations.\n"
        "Use ONLY the retrieved evidence below.\n"
        "ANTI-HALLUCINATION (mandatory):\n"
        "- If an AUTHORITATIVE MUTATION RECORD is present, it is ground truth.\n"
        "- Never invent files, dirs, IPs, users, packages, or errors not in evidence.\n"
        "- Never claim a path exists unless evidence or the mutation record says so.\n"
        "- Successful mkdir/touch/rm/echo-with-redirect: output NOTHING (empty).\n"
        "- apt install: only 'already newest' theater from command_effects evidence.\n"
        "- Do NOT mention AI, LLM, RAG, honeypot, or simulation.\n"
        "- Do NOT mix OTHER attackers' artifacts into this shell.\n"
        "\n"
        "Other rules:\n"
        "- Common tools (sudo, apt, nmap, curl, id, whoami, uname) EXIST here.\n"
        "- nmap/curl: fake lore from evidence only — never real network I/O.\n"
        "- Unknown junk words: bash: <cmd>: command not found\n"
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


def _demo_mark_enabled() -> bool:
    """When true, prefix LLM replies with [llm] so demos are obvious."""
    return os.environ.get("NETOSIS_LLM_DEMO_MARK", "1").strip().lower() not in {
        "0",
        "false",
        "no",
        "off",
    }


def _mark_llm_text(text: str) -> str:
    # Successful create/delete is silent on real bash — keep empty unmarked.
    if not text.strip():
        return ""
    if not _demo_mark_enabled():
        return text
    lines = text.splitlines(keepends=True)
    out: list[str] = []
    for line in lines:
        if line.strip() == "":
            out.append(line)
            continue
        if line.startswith("[llm]"):
            out.append(line)
            continue
        if line.endswith("\n"):
            out.append(f"[llm] {line}")
        else:
            out.append(f"[llm] {line}\n")
    return "".join(out)


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
        f"Command:\n{command}\n"
        "Respond with ONLY what a real bash shell would print for this command "
        "given the evidence. Prefer empty output when the mutation record says "
        "create/delete succeeded."
    )
    llm = client or get_llm_client()
    text = llm.complete(system, user).strip("\n")
    if text:
        text = text + "\n"
    if text.startswith("```"):
        lines = [ln for ln in text.splitlines() if not ln.strip().startswith("```")]
        text = "\n".join(lines).lstrip("\n")
        if text and not text.endswith("\n"):
            text += "\n"

    text = _mark_llm_text(text)

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


def narrate_after_mutation(
    session: Session,
    command: str,
    *,
    client: LlmClient | None = None,
) -> CommandResult:
    """FS already mutated deterministically — LLM prints grounded shell output only."""
    ctx = retrieve_context(session, command, include_mutation_authority=True)
    return generate_response(session, command, ctx, client=client)


# Compat helpers used by older tests
def build_system_prompt(session: Session, command: str) -> str:
    return _system_prompt(retrieve_context(session, command))
