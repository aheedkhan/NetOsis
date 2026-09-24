"""OpenAI-compatible chat client for local Qwen (Ollama / vLLM / NIM).

Default for this lab (CPU-only, shared with Proxmox): qwen2.5:3b via Ollama.
See docs/llm-local.md.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request


class OpenAICompatibleClient:
    """Minimal chat.completions client — no heavy SDK required."""

    def __init__(
        self,
        *,
        base_url: str | None = None,
        api_key: str | None = None,
        model: str | None = None,
        timeout_s: float = 60.0,
        max_tokens: int = 256,
        temperature: float = 0.2,
    ) -> None:
        self.base_url = (
            base_url
            or os.environ.get("NETOSIS_LLM_BASE_URL")
            or os.environ.get("NVIDIA_BASE_URL")
            or "http://127.0.0.1:11434/v1"
        ).rstrip("/")
        self.api_key = (
            api_key
            or os.environ.get("NETOSIS_LLM_API_KEY")
            or os.environ.get("NVIDIA_API_KEY")
            or "not-needed"
        )
        self.model = (
            model
            or os.environ.get("NETOSIS_LLM_MODEL")
            or "qwen2.5:3b"
        )
        self.timeout_s = float(os.environ.get("NETOSIS_LLM_TIMEOUT", str(timeout_s)))
        self.max_tokens = int(os.environ.get("NETOSIS_LLM_MAX_TOKENS", str(max_tokens)))
        self.temperature = float(os.environ.get("NETOSIS_LLM_TEMPERATURE", str(temperature)))

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        url = f"{self.base_url}/chat/completions"
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                body = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"LLM HTTP {exc.code}: {detail}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"LLM unreachable at {url}: {exc}") from exc

        choices = body.get("choices") or []
        if not choices:
            raise RuntimeError(f"LLM returned no choices: {body!r}")
        message = choices[0].get("message") or {}
        content = message.get("content")
        if not isinstance(content, str):
            raise RuntimeError(f"LLM missing message.content: {body!r}")
        return content
