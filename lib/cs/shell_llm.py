"""
Dynamic shell fallback — an LLM improvises for commands outside the scripted
set, off the interactive shell's turn, never on the decision plane's hot path.

Why this exists at all. A fixed command dispatcher — however wide — is
fingerprintable: an operator who tries `vim`, `python3 -c ...`, `tar`,
`awk`, anything not on the list gets an instant, suspiciously uniform
"command not found" that a real, lightly-provisioned Ubuntu box would not
produce for half of those. Routing the long tail through a local model
closes that gap the way Cowrie and its lookalikes cannot, since they only
ever get wider dispatch tables.

Why this is *not* on the decision plane's fast path. `docs/SCOPE-STATUS.md`
rules out "LLM in the fast request path (<100ms budget)" explicitly, and
that constraint is about the escalate/block *decision*, computed from
already-logged evidence — it says nothing about how long an individual shell
command is allowed to take to echo back. A real compromised host has network
and disk latency too; a few seconds of lag on an unusual command is
consistent with the fiction, not a violation of the budget the constraint
was written to protect.

Why every improvisation is memoized. An operator who runs the same command
twice, or a *different* operator who tries the same thing, must see the same
answer — a shell that improvises a fresh, different answer each time is a
far more obvious tell than not knowing the command at all. `_CACHE` keys on
(cwd, command) and is populated once, for the life of the process; the
static VirtualFS tree stays the authoritative "ground truth" for everything
it already covers; this only ever fills gaps.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import urllib.error
import urllib.request

# Qwen3 is a reasoning model — without an explicit think:false it emits its
# chain-of-thought as <think>...</think> before the actual answer, which
# would print straight into the SSH session as obvious garbage and both blow
# the cover instantly and roughly triple the response time. think:false on
# the request is the primary control; the regex strip is a second line of
# defence in case a future model/Ollama version answers inside think tags
# regardless of the flag.
_THINK_TAG = re.compile(r"<think>.*?</think>\s*", re.DOTALL)

ENABLED = os.environ.get("CS_SHELL_LLM_ENABLED", "0") == "1"
OLLAMA_HOST = os.environ.get("CS_OLLAMA_HOST", "host.containers.internal")
# Ollama's default bind is 127.0.0.1 only, invisible from a container even
# with host routing available — see deploy notes in README for the userspace
# socat proxy (127.0.0.1:11434 -> 0.0.0.0:11435) this default port assumes,
# which needs no changes to the host's own Ollama service or its systemd
# unit. Point CS_OLLAMA_PORT at 11434 directly if OLLAMA_HOST=0.0.0.0 is set
# on the host instead.
OLLAMA_PORT = int(os.environ.get("CS_OLLAMA_PORT", "11435"))
MODEL = os.environ.get("CS_SHELL_LLM_MODEL", "huihui_ai/qwen3-abliterated:30b")
# Measured ~11-12s end to end for a short command with thinking disabled on
# this model/hardware. Set generously above that rather than tightly against
# it — a timeout that fires on a normal-latency response is worse than a
# slightly slower shell, since it forces the generic fallback and wastes the
# generation that was about to arrive.
TIMEOUT_S = float(os.environ.get("CS_SHELL_LLM_TIMEOUT", "25"))

_CACHE: dict[tuple[str, str], str] = {}

_SYSTEM_PROMPT = """You are a Linux bash shell on a real, unremarkable Ubuntu \
24.04 server called intranet-web-01, belonging to a mid-size industrial \
company (NexusCorp). You are NOT an assistant and must never say you are \
one, never mention AI, never break character, never add commentary. Output \
ONLY the raw terminal text a real shell would print for the given command \
in the given directory - nothing else, no markdown, no code fences, no \
explanation.

Rules:
- If the command is a real, common Linux/bash command, produce plausible,
  boring, realistic output consistent with a lightly used engineering
  server. Keep it short - a real terminal is terse.
- If the command references a file or path not listed in the directory
  context below, respond as a real shell would for a missing file
  ("No such file or directory" or similar), not by inventing new files.
- If the command is destructive, requires root, or would need a real
  network/package index (apt-get install, rm -rf /, mkfs, reboot, useradd),
  respond exactly as a permission-restricted lightly-provisioned host would:
  a permission error or "command not found" - never actually simulate the
  action succeeding.
- Never output more than 15 lines.
"""


def _prompt(cmd: str, cwd: str, listing: list[str]) -> str:
    entries = ", ".join(listing) if listing else "(empty)"
    return (
        f"Current directory: {cwd}\n"
        f"Directory contents: {entries}\n"
        f"Command: {cmd}\n"
        f"Output:"
    )


def _call_ollama(cmd: str, cwd: str, listing: list[str]) -> str | None:
    """Blocking HTTP call — always run via asyncio.to_thread, never inline
    on an asyncssh callback (see module docstring)."""
    payload = {
        "model": MODEL,
        "system": _SYSTEM_PROMPT,
        "prompt": _prompt(cmd, cwd, listing),
        "stream": False,
        "think": False,
        "options": {"num_predict": 300, "temperature": 0.4},
    }
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        f"http://{OLLAMA_HOST}:{OLLAMA_PORT}/api/generate",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_S) as resp:
            body = json.loads(resp.read())
        text = str(body.get("response") or "")
        text = _THINK_TAG.sub("", text).strip()
        return text or None
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError):
        return None


async def improvise(cmd: str, cwd: str, listing: list[str]) -> str | None:
    """The one entry point. Returns None on any failure or if disabled —
    callers must have a realistic non-LLM fallback ready either way."""
    if not ENABLED:
        return None
    key = (cwd, cmd.strip())
    if key in _CACHE:
        return _CACHE[key]
    result = await asyncio.to_thread(_call_ollama, cmd, cwd, listing)
    if result:
        _CACHE[key] = result
    return result
