"""Classify virtual FS / package mutations into policy risk categories."""

from __future__ import annotations

from deception.runtime.host import Session

_SENSITIVE_PREFIXES = (
    "/etc",
    "/root",
    "/var/www",
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/boot",
    "/opt",
    "/var/spool",
)

_TMP_PREFIXES = ("/tmp", "/var/tmp")


def path_sensitivity(path: str) -> str:
    """Return 'tmp' | 'sensitive' | 'normal' for a virtual path."""
    p = path if path == "/" else path.rstrip("/") or "/"
    for pref in _TMP_PREFIXES:
        if p == pref or p.startswith(pref + "/"):
            return "tmp"
    for pref in _SENSITIVE_PREFIXES:
        if p == pref or p.startswith(pref + "/"):
            return "sensitive"
    return "normal"


def mutation_risk_category(session: Session) -> str | None:
    """Pick the strongest risk category for this command's mutation batch."""
    if session.last_packages:
        return "Package_install"

    created = session.last_created or []
    deleted = session.last_deleted or []

    if created:
        levels = {path_sensitivity(p) for p in created}
        if "sensitive" in levels:
            return "FS_create_sensitive"
        if levels == {"tmp"}:
            return "FS_create_tmp"
        return "FS_create"

    if deleted:
        levels = {path_sensitivity(p) for p in deleted}
        if "sensitive" in levels:
            return "FS_delete_sensitive"
        return "FS_delete"

    return None
