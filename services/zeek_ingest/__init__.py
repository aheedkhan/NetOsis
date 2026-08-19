"""Tail Zeek JSON logs and emit canonical events."""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

from cs.events import new_event
from cs.ingest import emit
from cs.tinyhttp import wait_http

ZEEK_DIR = Path(os.environ.get("CS_ZEEK_LOG_DIR", "/zeek/logs"))
LOGGER_HOST = os.environ.get("CS_LOGGER_HOST", "10.200.1.10")
LOGGER_PORT = int(os.environ.get("CS_LOGGER_PORT", "8088"))
POLL = float(os.environ.get("CS_ZEEK_POLL", "0.4"))

WATCH = ("ssh.log", "ssl.log", "conn.log", "http.log")


def _get(rec: dict, *keys):
    for key in keys:
        if key in rec and rec[key] not in (None, "-"):
            return rec[key]
    ident = rec.get("id")
    if isinstance(ident, dict):
        for key in keys:
            short = key.split(".")[-1] if "." in key else key
            if short in ident:
                return ident[short]
    return None


def _port(rec: dict, *keys):
    val = _get(rec, *keys)
    try:
        return int(val) if val is not None else None
    except (TypeError, ValueError):
        return None


def _ts(rec: dict) -> str | None:
    ts = rec.get("ts")
    if isinstance(ts, str) and "T" in ts:
        return ts
    return None


def _stamp(event: dict, rec: dict) -> dict:
    ts = _ts(rec)
    if ts:
        event["@timestamp"] = ts
    return event


def map_ssh(rec: dict) -> dict:
    src = _get(rec, "id.orig_h")
    dst = _get(rec, "id.resp_h")
    hassh = _get(rec, "hassh")
    event = new_event(
        dataset="cybersnare.zeek.ssh",
        action="ssh-handshake",
        category=["network"],
        capability="ssh",
        source_ip=src,
        source_port=_port(rec, "id.orig_p"),
        dest_ip=dst,
        dest_port=_port(rec, "id.resp_p"),
        dest_service="ssh",
        session_id=_get(rec, "uid"),
        hassh=str(hassh) if hassh else None,
        extra={
            "ssh": {
                "client_version": _get(rec, "client"),
                "server_version": _get(rec, "server"),
                "hasshAlgorithms": _get(rec, "hasshAlgorithms"),
            }
        },
    )
    return _stamp(event, rec)


def map_ssl(rec: dict) -> dict:
    ja4 = _get(rec, "ja4") or _get(rec, "ja4s")
    event = new_event(
        dataset="cybersnare.zeek.ssl",
        action="tls-client-hello",
        category=["network"],
        capability="http",
        source_ip=_get(rec, "id.orig_h"),
        source_port=_port(rec, "id.orig_p"),
        dest_ip=_get(rec, "id.resp_h"),
        dest_port=_port(rec, "id.resp_p"),
        dest_service="https",
        session_id=_get(rec, "uid"),
        ja4=str(ja4) if ja4 else None,
        extra={
            "tls": {
                "server_name": _get(rec, "server_name"),
                "version": _get(rec, "version"),
                "cipher": _get(rec, "cipher"),
            }
        },
    )
    return _stamp(event, rec)


def map_conn(rec: dict) -> dict:
    proto = _get(rec, "proto") or "tcp"
    service = _get(rec, "service")
    event = new_event(
        dataset="cybersnare.zeek.conn",
        action="connection",
        category=["network"],
        capability="sensor",
        source_ip=_get(rec, "id.orig_h"),
        source_port=_port(rec, "id.orig_p"),
        dest_ip=_get(rec, "id.resp_h"),
        dest_port=_port(rec, "id.resp_p"),
        dest_service=service,
        session_id=_get(rec, "uid"),
        extra={"network_conn": {"protocol": proto, "service": service}},
    )
    return _stamp(event, rec)


def map_http(rec: dict) -> dict:
    event = new_event(
        dataset="cybersnare.zeek.http",
        action="http-request",
        category=["web"],
        capability="http",
        source_ip=_get(rec, "id.orig_h"),
        source_port=_port(rec, "id.orig_p"),
        dest_ip=_get(rec, "id.resp_h"),
        dest_port=_port(rec, "id.resp_p"),
        dest_service="http",
        session_id=_get(rec, "uid"),
        ua_signature=_get(rec, "user_agent"),
        extra={
            "http": {
                "request": {
                    "method": _get(rec, "method"),
                    "host": _get(rec, "host"),
                    "uri": _get(rec, "uri"),
                }
            }
        },
    )
    return _stamp(event, rec)


MAPPERS = {
    "ssh.log": map_ssh,
    "ssl.log": map_ssl,
    "conn.log": map_conn,
    "http.log": map_http,
}


class Tail:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.offset = 0
        self.inode: int | None = None

    def read_new_lines(self) -> list[str]:
        if not self.path.exists():
            return []
        stat = self.path.stat()
        if self.inode is not None and stat.st_ino != self.inode:
            self.offset = 0
        if stat.st_size < self.offset:
            self.offset = 0
        self.inode = stat.st_ino
        with self.path.open(encoding="utf-8", errors="replace") as fh:
            fh.seek(self.offset)
            data = fh.read()
            self.offset = fh.tell()
        if not data:
            return []
        return [ln for ln in data.splitlines() if ln.strip()]


async def main() -> None:
    await wait_http(LOGGER_HOST, LOGGER_PORT, "/health")
    ZEEK_DIR.mkdir(parents=True, exist_ok=True)
    tails = {name: Tail(ZEEK_DIR / name) for name in WATCH}
    print(f"zeek-ingest watching {ZEEK_DIR}", flush=True)
    while True:
        for name, tail in tails.items():
            mapper = MAPPERS[name]
            for line in tail.read_new_lines():
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(rec, dict):
                    continue
                try:
                    event = mapper(rec)
                    await emit(event)
                except Exception as exc:
                    print(f"ingest {name} failed: {exc}", flush=True)
        await asyncio.sleep(POLL)


if __name__ == "__main__":
    asyncio.run(main())
