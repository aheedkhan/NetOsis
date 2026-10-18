"""Time helpers so every fake host has a consistent, believable past.

Boot time, file ages and log lines are all derived from the real clock plus
fixed offsets in the host YAML — the same host shows the same uptime / dates
to every attacker on the same day.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone


def now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def parse(ts: str) -> datetime:
    """Accept 'YYYY-MM-DD', 'YYYY-MM-DD HH:MM' or 'YYYY-MM-DD HH:MM:SS'."""
    ts = ts.strip().replace("T", " ").rstrip("Z")
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            return datetime.strptime(ts, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return now()


def stamp(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def jitter(seed: str, span_minutes: int) -> timedelta:
    """Deterministic offset in [0, span) so file dates differ but never change."""
    h = int(hashlib.sha256(seed.encode()).hexdigest()[:8], 16)
    return timedelta(minutes=h % max(span_minutes, 1))


def boot_time(system: dict) -> datetime:
    days = int(system.get("uptime_days", 47))
    base = (now() - timedelta(days=days)).replace(hour=3, minute=12, second=44)
    return base


def ls_time(dt: datetime) -> str:
    """`ls -l` style: recent files show time, older than ~6 months show year."""
    if (now() - dt).days > 180 or dt > now():
        return dt.strftime("%b %e  %Y")
    return dt.strftime("%b %e %H:%M")


def uptime_text(system: dict) -> tuple[str, int]:
    """('47 days,  3:41', minutes) for uptime/w."""
    delta = now() - boot_time(system)
    days = delta.days
    hours, rem = divmod(delta.seconds, 3600)
    minutes = rem // 60
    if days:
        text = f"{days} day{'s' if days != 1 else ''}, {hours:2d}:{minutes:02d}"
    else:
        text = f"{hours:2d}:{minutes:02d}"
    return text, int(delta.total_seconds() // 60)
