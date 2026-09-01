"""
Layered virtual filesystem — the L2/L3 engagement surface.

Two things distinguish a deception filesystem that actually holds an
operator's attention from one that gives itself away in the first `ls`:
depth that expands as they earn it, and content that reads as something a
real engineer left behind rather than a wordlist. Neither is achieved by
inventing content at request time — an LLM asked to produce "a realistic
config file" on the spot tends to produce exactly the generic, slightly-too-
tidy text that reads as generated. This module is instead hand-authored
against the same fictional company already built for the DMZ sites
(deploy/org/sites/generate.py) and the org topology (config/topology.json),
so a careful operator who cross-checks a name or a hostname against the
public site or a `getent hosts` finds them consistent — which is exactly the
kind of check a careful operator makes, and exactly what breaks the
deception when two parts of a honeypot were authored independently.

Layering. Two tiers, matching the L2/L3 manifests:

  L2 (shallow)  — a guest home directory. Boring, but not empty: a
                  half-finished note and a shell history are what make a
                  freshly-provisioned decoy look inhabited rather than staged,
                  and the history is a breadcrumb — it names a path the L3
                  tier actually has, so an operator who reads it before
                  wandering off finds a next step, and one who doesn't is
                  quietly less deep into the story despite equal access. That
                  difference is itself a behavioural signal.

  L3 (deep)     — /opt/nexuscorp, an internal engineering tree consistent
                  with the company's stated business (industrial control /
                  SCADA), plus a credentials file that is the honeytoken: a
                  password for hosts that are real addresses in this lab
                  (dc01.nexuscorp.local etc, the decoy corp hosts already
                  built). Using it is the L3 "internal hop" the design record
                  describes, and it is now a real, walkable path rather than
                  a manifest field with no content behind it.

Every node the shell can name is a `Node`. `VirtualFS.resolve()` is the only
way in — it enforces the layer gate, so a path that exists in the L3 tree is
invisible (not merely "permission denied", genuinely absent) below L3, which
is what makes depth mean something rather than being an access-control label
on an otherwise-static tree.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

# --------------------------------------------------------------------------
# Node model
# --------------------------------------------------------------------------

# How far in the past a file's mtime sits, in days. A tight range per role
# keeps files that were "written together" close in time (a script and its
# README) while spreading the tree as a whole across a plausible history —
# nothing in a real, months-old checkout has a single timestamp.
_AGE_DAYS = {
    "ancient": (280, 420),
    "old": (120, 260),
    "recent": (14, 90),
    "fresh": (1, 10),
}


@dataclass
class Node:
    name: str
    kind: str  # "dir" | "file"
    min_level: str = "L2"  # the shallowest level this node is visible at
    content: str = ""
    owner: str = "guest"
    group: str = "guest"
    mode: str = "-rw-r--r--"
    age: str = "recent"
    sensitivity: str | None = None  # None | "sensitive" | "honeytoken"
    children: dict[str, "Node"] = field(default_factory=dict)

    def is_dir(self) -> bool:
        return self.kind == "dir"


_LEVEL_RANK = {"L0": 0, "L1": 1, "L2": 2, "L3": 3, "BURN": 4, "BLOCK": 5}


def _level_ok(node_level: str, current_level: str) -> bool:
    return _LEVEL_RANK.get(current_level, 0) >= _LEVEL_RANK.get(node_level, 0)


# --------------------------------------------------------------------------
# Content — authored once, consistent with deploy/org/sites/generate.py
# --------------------------------------------------------------------------

_BASH_HISTORY = """cd /opt
ls
cd nexuscorp
cat README.md
./scada-sync.sh --dry-run
vim deploy.sh
cd ..
history -c
"""

_HOME_NOTES = """TODO before Friday standup
- ping Tomasz re: the staging deploy key rotation (overdue since June)
- Priya wants the historian export job moved off db01 onto its own box
- follow up with service desk about the VPN cert expiring next month
- remember to actually read the SCADA sync runbook before touching it again
"""

_README_NEXUSCORP = """# NexusCorp internal tooling

Deployment and sync scripts for the plant-floor historian and the SCADA
gateway integration. Ask Priya (SCADA) or Tomasz (Platform) before touching
scada-sync.sh in anything other than --dry-run — the last time someone ran
it live against the wrong environment it took the historian offline for
four hours.

Directories:
  scada-sync.sh   sync job, plant historian <-> ERP staging
  deploy.sh       app deploy helper, reads config/db.env
  config/         connection strings and service accounts (do NOT commit)
  runbooks/       on-call notes

Internal hosts referenced below are on the corp VLAN, not reachable from
this box directly except where noted.
"""

_SCADA_SYNC_SH = """#!/bin/bash
# scada-sync.sh -- plant historian -> ERP staging sync
# Owner: p.raghunathan (SCADA). Do not run outside --dry-run without asking.
set -euo pipefail

source "$(dirname "$0")/config/db.env"

if [ "${1:-}" != "--dry-run" ]; then
  echo "Live sync against $HISTORIAN_HOST -- confirm with Priya first." >&2
fi

echo "[scada-sync] connecting to $HISTORIAN_HOST as $HISTORIAN_USER"
echo "[scada-sync] staging target: $ERP_STAGING_HOST"
echo "[scada-sync] dry-run: would sync last 24h of tag history"
"""

_DEPLOY_SH = """#!/bin/bash
# deploy.sh -- push the current build to the internal app hosts.
# Reads config/db.env for the app service account. Ask Tomasz if this fails.
set -euo pipefail
source "$(dirname "$0")/config/db.env"

TARGETS=(dc01.nexuscorp.local fs01.nexuscorp.local erp01.nexuscorp.local)

for host in "${TARGETS[@]}"; do
  echo "[deploy] pushing build to $host as $APP_SVC_USER"
  scp -q -o StrictHostKeyChecking=no build.tar.gz "$APP_SVC_USER@$host:/opt/app/incoming/" || \
    echo "[deploy] WARN: $host unreachable from this host, skipping"
done
"""

# The honeytoken. Deliberately plausible, deliberately reused across the
# service account so a real operator would try it more than once — that
# repetition is itself evidence, not a wasted opportunity.
_DB_ENV = """# db.env -- service account for scada-sync and deploy.
# Rotated quarterly. Last rotation: see runbooks/rotation-log.md
HISTORIAN_HOST=dc01.nexuscorp.local
HISTORIAN_USER=svc_historian
HISTORIAN_PASS=Nexus!Hist0rian24
ERP_STAGING_HOST=erp01.nexuscorp.local
APP_SVC_USER=svc_deploy
APP_SVC_PASS=D3ploy_Nexus#2024
"""

_ROTATION_LOG = """# Credential rotation log

2026-04-02  svc_historian, svc_deploy rotated (Tomasz)
2026-01-08  svc_historian, svc_deploy rotated (Tomasz)
2025-10-11  svc_historian, svc_deploy rotated (Priya, emergency -- see incident #214)
2025-07-03  svc_historian, svc_deploy rotated (Tomasz)

Next due: 2026-07. If you're reading this after that date, rotate before
you deploy anything -- ping Tomasz.
"""

_INCIDENT_214 = """# Incident 214 -- historian sync ran against prod by mistake

Summary: scada-sync.sh was run without --dry-run against the wrong
HISTORIAN_HOST (prod instead of staging), overwriting six hours of tag
history on db01 before anyone noticed the row counts looked wrong.

Root cause: config/db.env on a laptop was stale (pointed at prod), and the
script has no environment confirmation prompt.

Follow-up: rotated the service account (see rotation-log.md), added the
--dry-run warning text, still haven't added the confirmation prompt because
nobody's had time. Don't be the reason we finally add it the hard way.

-- Priya, 2025-10-11
"""

_SSH_KNOWN_HOSTS = """dc01.nexuscorp.local ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKzR3qk8mF2h9xVtqWvY7uJp1nL4mR8sT2wA6bC9dE0f
fs01.nexuscorp.local ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIN5tY8vQ2mK6hR9wL3pB7cD1eF4gH8iJ0kM2nO5q
erp01.nexuscorp.local ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIP7sT1uV4wX9yZ2aB5cD8eF1gH4iJ7kL0mN3oQ6r
"""

_OS_RELEASE = """PRETTY_NAME="Ubuntu 24.04.2 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
VERSION="24.04.2 LTS (Noble Numbat)"
ID=ubuntu
ID_LIKE=debian
"""

_MOTD = """Welcome to intranet-web-01 (NexusCorp internal)

This system is for authorised NexusCorp staff and contractors only. All
activity is logged. If you're unsure why you have access, contact the
service desk (ext. 4400) before doing anything.
"""

_VAR_LOG_AUTH = """{ts0} intranet-web-01 sshd[2214]: Accepted password for guest from 10.10.20.50 port 51422 ssh2
{ts1} intranet-web-01 sshd[2214]: pam_unix(sshd:session): session opened for user guest
{ts2} intranet-web-01 CRON[1188]: (root) CMD (/usr/lib/php/sessionclean)
{ts3} intranet-web-01 sshd[2401]: Accepted password for guest from 10.10.20.50 port 51988 ssh2
"""

_CRONTAB = """# m h  dom mon dow   command
0 2 * * * /opt/nexuscorp/scada-sync.sh --dry-run >> /var/log/scada-sync.log 2>&1
15 3 * * 0 /usr/local/bin/backup-nightly.sh
"""


def _fmt_ts(days_ago_min: int, days_ago_max: int, seed: int) -> str:
    """Deterministic pseudo-random timestamp within a window, syslog format."""
    span = max(days_ago_max - days_ago_min, 1)
    days_ago = days_ago_min + (seed * 2654435761 % span)
    dt = datetime.now(timezone.utc) - timedelta(days=days_ago, hours=(seed * 7) % 24)
    return dt.strftime("%b %d %H:%M:%S")


def _build_tree() -> Node:
    root = Node("/", "dir", min_level="L2")

    home = Node("home", "dir", min_level="L2")
    guest = Node("guest", "dir", min_level="L2")
    guest.children[".bash_history"] = Node(
        ".bash_history", "file", min_level="L2", content=_BASH_HISTORY,
        mode="-rw-------", age="fresh",
    )
    guest.children["notes.txt"] = Node(
        "notes.txt", "file", min_level="L2", content=_HOME_NOTES, age="recent",
    )
    guest.children["documents"] = Node("documents", "dir", min_level="L2")
    guest.children["downloads"] = Node("downloads", "dir", min_level="L2")
    home.children["guest"] = guest
    root.children["home"] = home

    etc = Node("etc", "dir", min_level="L2")
    etc.children["os-release"] = Node("os-release", "file", min_level="L2", content=_OS_RELEASE, age="ancient")
    etc.children["hostname"] = Node("hostname", "file", min_level="L2", content="intranet-web-01\n", age="ancient")
    etc.children["motd"] = Node("motd", "file", min_level="L2", content=_MOTD, age="old")
    root.children["etc"] = etc

    var = Node("var", "dir", min_level="L2")
    log = Node("log", "dir", min_level="L2")
    log.children["auth.log"] = Node(
        "auth.log", "file", min_level="L2",
        content=_VAR_LOG_AUTH.format(
            ts0=_fmt_ts(1, 3, 1), ts1=_fmt_ts(1, 3, 2),
            ts2=_fmt_ts(0, 1, 3), ts3=_fmt_ts(0, 1, 4),
        ),
        age="fresh", owner="root", group="adm", mode="-rw-r-----",
    )
    log.children["scada-sync.log"] = Node(
        "scada-sync.log", "file", min_level="L3",
        content="[dry-run] would sync last 24h of tag history\n" * 3,
        age="fresh",
    )
    var.children["log"] = log
    root.children["var"] = var

    # ---- L3 only, from here down --------------------------------------
    opt = Node("opt", "dir", min_level="L3")
    nexuscorp = Node("nexuscorp", "dir", min_level="L3", mode="drwxr-xr-x", owner="root", group="staff")
    nexuscorp.children["README.md"] = Node(
        "README.md", "file", min_level="L3", content=_README_NEXUSCORP, age="old",
        owner="tomasz", group="staff",
    )
    nexuscorp.children["scada-sync.sh"] = Node(
        "scada-sync.sh", "file", min_level="L3", content=_SCADA_SYNC_SH,
        mode="-rwxr-xr-x", age="old", owner="praghunathan", group="staff",
    )
    nexuscorp.children["deploy.sh"] = Node(
        "deploy.sh", "file", min_level="L3", content=_DEPLOY_SH,
        mode="-rwxr-xr-x", age="recent", sensitivity="sensitive",
        owner="tomasz", group="staff",
    )
    config = Node("config", "dir", min_level="L3", mode="drwx------", owner="tomasz", group="staff")
    config.children["db.env"] = Node(
        "db.env", "file", min_level="L3", content=_DB_ENV,
        mode="-rw-------", age="recent", sensitivity="honeytoken",
        owner="tomasz", group="staff",
    )
    nexuscorp.children["config"] = config
    runbooks = Node("runbooks", "dir", min_level="L3", owner="tomasz", group="staff")
    runbooks.children["rotation-log.md"] = Node(
        "rotation-log.md", "file", min_level="L3", content=_ROTATION_LOG,
        age="recent", sensitivity="sensitive", owner="tomasz", group="staff",
    )
    runbooks.children["incident-214.md"] = Node(
        "incident-214.md", "file", min_level="L3", content=_INCIDENT_214, age="old",
        owner="praghunathan", group="staff",
    )
    nexuscorp.children["runbooks"] = runbooks
    opt.children["nexuscorp"] = nexuscorp
    root.children["opt"] = opt

    guest.children[".ssh"] = Node(".ssh", "dir", min_level="L3", mode="drwx------")
    guest.children[".ssh"].children["known_hosts"] = Node(
        "known_hosts", "file", min_level="L3", content=_SSH_KNOWN_HOSTS,
        mode="-rw-r--r--", age="recent", sensitivity="sensitive",
    )

    var_spool = Node("spool", "dir", min_level="L3")
    var_spool.children["cron"] = Node("cron", "dir", min_level="L3")
    var_spool.children["cron"].children["crontabs"] = Node(
        "crontabs", "dir", min_level="L3",
    )
    var_spool.children["cron"].children["crontabs"].children["root"] = Node(
        "root", "file", min_level="L3", content=_CRONTAB, mode="-rw-------", age="old",
    )
    var.children["spool"] = var_spool

    return root


_TREE = _build_tree()


# --------------------------------------------------------------------------
# Filesystem interface
# --------------------------------------------------------------------------

@dataclass
class ResolveResult:
    node: Node | None
    abs_path: str
    exists: bool
    visible: bool  # exists AND visible at the caller's level


def _normalize(path: str, cwd: str) -> str:
    if not path.startswith("/"):
        path = cwd.rstrip("/") + "/" + path
    parts: list[str] = []
    for part in path.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if parts:
                parts.pop()
            continue
        parts.append(part)
    return "/" + "/".join(parts)


class VirtualFS:
    """Read-only, level-gated view over the authored tree."""

    def __init__(self, level: str) -> None:
        self.level = level

    def resolve(self, path: str, cwd: str) -> ResolveResult:
        abs_path = _normalize(path, cwd)
        node = _TREE
        for part in [p for p in abs_path.split("/") if p]:
            if not node.is_dir() or part not in node.children:
                return ResolveResult(None, abs_path, False, False)
            node = node.children[part]
        visible = _level_ok(node.min_level, self.level)
        return ResolveResult(node, abs_path, True, visible)

    def listing(self, node: Node) -> list[Node]:
        return [c for c in node.children.values() if _level_ok(c.min_level, self.level)]

    def mtime_str(self, node: Node, *, long: bool = False) -> str:
        lo, hi = _AGE_DAYS.get(node.age, _AGE_DAYS["recent"])
        seed = sum(ord(c) for c in node.name) + len(node.content)
        days_ago = lo + (seed % max(hi - lo, 1))
        dt = datetime.now(timezone.utc) - timedelta(days=days_ago)
        if long:
            return dt.strftime("%b %d %H:%M")
        return dt.strftime("%b %d  %Y") if days_ago > 180 else dt.strftime("%b %d %H:%M")

    def ls_line(self, node: Node) -> str:
        kind = "d" if node.is_dir() else "-"
        # `mode` is only meaningful once explicitly set for a directory (a few
        # are, e.g. mode="drwx------" for .ssh); the dataclass default
        # ("-rw-r--r--") is a *file* default and would otherwise print a
        # directory with no execute bit, which no real `ls -la` ever shows.
        if node.mode.startswith("d"):
            mode = node.mode[1:]
        elif node.is_dir():
            mode = "rwxr-xr-x"
        else:
            mode = node.mode[1:]
        size = 4096 if node.is_dir() else max(len(node.content), 32)
        return f"{kind}{mode} 1 {node.owner:<8} {node.group:<8} {size:>6} {self.mtime_str(node)} {node.name}"
