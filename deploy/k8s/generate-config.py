#!/usr/bin/env python3
"""
Generate the cs-manifests ConfigMap (the manifest-*.json capability ladder the
decision plane mounts at CS_CONFIG_DIR) from config/*.json.

Usage:
    python3 deploy/k8s/generate-config.py > deploy/k8s/generated/config.yaml
"""

from __future__ import annotations

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
CONFIG = ROOT / "config"

# Only the decision plane's own inputs — shell-users.json and
# supervisor-approval.json are consumed by the ssh_surface / gate script, not
# the decision plane, and stay out of this particular ConfigMap.
FILES = (
    "manifest-p0.json",
    "manifest-l0.json",
    "manifest-l1.json",
    "manifest-l2.json",
    "manifest-l3.json",
    "manifest-burn.json",
    "manifest-block.json",
)


def indent(text: str, spaces: int) -> str:
    pad = " " * spaces
    return "\n".join(pad + line if line else line for line in text.splitlines())


def manifests_configmap() -> str:
    entries = []
    for name in FILES:
        path = CONFIG / name
        entries.append(f"  {name}: |\n{indent(path.read_text(encoding='utf-8'), 4)}")
    body = "\n".join(entries)
    return f"""apiVersion: v1
kind: ConfigMap
metadata:
  name: cs-manifests
  namespace: cs-control
data:
{body}
"""


def shell_users_configmap() -> str:
    content = (CONFIG / "shell-users.json").read_text(encoding="utf-8")
    parts = []
    for ns in ("cs-deception",):
        parts.append(f"""apiVersion: v1
kind: ConfigMap
metadata:
  name: cs-shell-users
  namespace: {ns}
data:
  shell-users.json: |
{indent(content, 4)}
""")
    return "---\n".join(parts)


def generate() -> str:
    return (
        "# GENERATED — do not hand-edit.\n"
        "# Source: config/*.json, generator: deploy/k8s/generate-config.py\n"
        + manifests_configmap()
        + "---\n"
        + shell_users_configmap()
    )


if __name__ == "__main__":
    sys.stdout.write(generate())
