"""Authoritative mutation grounding — LLM may narrate, never invent FS facts."""

from __future__ import annotations

from deception.runtime.host import Session


def mutation_authority_block(session: Session, command: str) -> str:
    """Facts the LLM MUST treat as ground truth for this command."""
    created = list(session.last_created or [])
    deleted = list(session.last_deleted or [])
    packages = list(session.last_packages or [])
    lines = [
        "AUTHORITATIVE MUTATION RECORD (do not contradict; do not invent extras):",
        f"command={command!r}",
        f"user={session.user} cwd={session.cwd} host={session.host.hostname}",
        f"created_paths={created or ['(none)']}",
        f"deleted_paths={deleted or ['(none)']}",
        f"packages_attempted_this_cmd={packages or ['(none)']}",
    ]
    # Snapshot parent listings for created paths (anti-hallucination)
    fs = session.host.filesystem
    for path in created[:12]:
        parent = path.rsplit("/", 1)[0] or "/"
        kids = sorted(
            {
                k[len(parent.rstrip('/') + '/') :].split("/")[0]
                for k in fs
                if k != parent and k.startswith((parent.rstrip("/") + "/") if parent != "/" else "/")
            }
        )
        if parent == "/":
            kids = sorted({k.lstrip("/").split("/")[0] for k in fs if k != "/"})
        meta = fs.get(path) or {}
        lines.append(
            f"exists_now {path} type={meta.get('type', '?')} "
            f"parent={parent} siblings_sample={kids[:20]}"
        )
    lines.append(
        "Shell rules: successful mkdir/touch/rm/echo-redirect → empty stdout; "
        "apt install → already-newest theater from command_effects evidence only."
    )
    return "\n".join(lines)
