#!/usr/bin/env python3
"""Benchmark Ollama models for honeypot latency (stdlib only).

Run on VM103, or from a honeypot CT with --url http://192.168.40.10:11434.
Pick the largest model whose p95 stays under ~4 s.
"""

from __future__ import annotations

import argparse
import json
import statistics
import time
import urllib.request

PROMPTS = [
    "df -h",
    "systemctl status nginx",
    "cat /etc/os-release",
    "netstat -tulpn",
    "crontab -l",
]
SYSTEM = (
    "You are a realistic Ubuntu 22.04 bash shell on host ent-web-01. "
    "Output ONLY terminal output. No markdown. No explanations."
)


def run(url: str, model: str, command: str, max_tokens: int) -> float:
    body = json.dumps(
        {
            "model": model,
            "messages": [
                {"role": "system", "content": SYSTEM},
                {"role": "user", "content": f"Command:\n{command}"},
            ],
            "max_tokens": max_tokens,
            "temperature": 0.2,
        }
    ).encode()
    req = urllib.request.Request(
        f"{url}/v1/chat/completions", data=body, headers={"Content-Type": "application/json"}
    )
    start = time.perf_counter()
    with urllib.request.urlopen(req, timeout=180) as resp:
        json.loads(resp.read())
    return time.perf_counter() - start


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:11434")
    ap.add_argument("--models", nargs="+", default=["qwen2.5:0.5b", "qwen2.5:1.5b", "qwen2.5:3b"])
    ap.add_argument("--max-tokens", type=int, default=128)
    args = ap.parse_args()

    print(f"{'model':<16} {'median s':>9} {'p95 s':>7}")
    for model in args.models:
        try:
            run(args.url, model, "uptime", args.max_tokens)  # warm-up / load into RAM
            times = sorted(run(args.url, model, c, args.max_tokens) for c in PROMPTS)
        except Exception as exc:
            print(f"{model:<16} error: {exc}")
            continue
        p95 = times[min(len(times) - 1, int(round(0.95 * (len(times) - 1))))]
        print(f"{model:<16} {statistics.median(times):>9.1f} {p95:>7.1f}")


if __name__ == "__main__":
    main()
