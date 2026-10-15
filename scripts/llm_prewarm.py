#!/usr/bin/env python3
"""Pre-generate fake-shell answers with a large model into the LLM cache.

Run ON a honeypot CT after lab-bootstrap-remote.sh (uses its .env + host YAML):

  cd /opt/netosis
  nohup .venv/bin/python scripts/llm_prewarm.py --model qwen2.5:3b > data/prewarm.log 2>&1 &
  tail -f data/prewarm.log

Live sessions then answer these commands instantly and identically, while the
small live model is only used for commands nobody pre-generated. Safe to stop
and re-run: already cached commands are skipped.
"""

from __future__ import annotations

import argparse
import os
import pwd
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Commands that reach the LLM (the deterministic engine answers ls/cat/ps/ip/id/...).
COMMANDS = """
uname -a
uname -r
uptime
w
who
last
lastlog
hostname
hostnamectl
df -h
df
du -sh /var/log
free -m
free -h
lscpu
lsblk
mount
nproc
lsb_release -a
env
printenv
history
crontab -l
systemctl list-units --type=service --state=running
systemctl status nginx
systemctl status ssh
service --status-all
ss -tulpn
ss -tan
netstat -tulpn
netstat -antp
ifconfig
route -n
arp -a
getent passwd
groups
last -n 10
journalctl -n 20
dmesg | tail
top -bn1 | head -15
which python3 gcc nc wget curl
python3 --version
openssl version
nginx -v
find / -perm -4000 -type f 2>/dev/null
find / -name "*.conf" 2>/dev/null | head
find /home -type f
iptables -L
ufw status
docker ps
mysql --version
psql --version
redis-cli ping
ping -c 3 192.168.30.254
ping -c 2 8.8.8.8
traceroute 8.8.8.8
dig google.com
nslookup finance-db-01
host finance-db-01
ssh-keygen -l -f /etc/ssh/ssh_host_ed25519_key.pub
date
timedatectl
locale
""".strip().splitlines()


def _load_dotenv(path: Path) -> None:
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        os.environ[key.strip()] = val.strip().strip("'\"")


def main() -> int:
    os.chdir(ROOT)
    _load_dotenv(ROOT / ".env")
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--model", default="qwen2.5:3b", help="large model for offline generation")
    ap.add_argument("--users", nargs="+", default=[os.environ.get("NETOSIS_SSH_USER", "admin"), "root"])
    ap.add_argument("--max-tokens", type=int, default=200)
    ap.add_argument("--timeout", type=float, default=300)
    args = ap.parse_args()

    os.environ["NETOSIS_LLM_CACHE"] = "1"
    os.environ["NETOSIS_LLM_MAX_TOKENS"] = str(args.max_tokens)
    os.environ["NETOSIS_LLM_TIMEOUT"] = str(args.timeout)

    from deception.llm.cache import cache_key, cache_path, get_cache
    from deception.llm.fallback import generate_response
    from deception.llm.openai_client import OpenAICompatibleClient
    from deception.runtime.host import Session, VirtualHost

    host_yaml = Path(os.environ.get("NETOSIS_HOST_CONFIG", "deception/hosts/enterprise-web.yml"))
    client = OpenAICompatibleClient(model=args.model)
    cache = get_cache()
    assert cache is not None
    print(f"[*] host={host_yaml} model={args.model} cache={cache_path()} ({len(cache)} cached)")

    todo = [(u, c) for u in args.users for c in COMMANDS]
    for i, (user, command) in enumerate(todo, 1):
        session = Session(host=VirtualHost.load(host_yaml), session_id="prewarm", user=user)
        if cache.get(cache_key(session, command)) is not None:
            continue
        start = time.perf_counter()
        result = generate_response(session, command, client=client)
        took = time.perf_counter() - start
        first = (result.stdout or result.stderr).strip().splitlines()[:1]
        print(f"[{i}/{len(todo)}] {took:5.1f}s {user}$ {command} -> {first[0][:70] if first else '(empty)'}",
              flush=True)

    try:  # service runs as `netosis` and must be able to add to the cache
        pw = pwd.getpwnam("netosis")
        os.chown(cache_path(), pw.pw_uid, pw.pw_gid)
    except (KeyError, PermissionError, FileNotFoundError):
        pass
    print(f"[+] done — {len(cache)} cached answers")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
