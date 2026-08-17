"""Stage-0 sinkhole: DNS and HTTP answered locally. Nothing leaves the egress network."""

from __future__ import annotations

import asyncio
import os
import socket
import struct
import uuid

from cs.events import new_event
from cs.ingest import emit_bg
from cs.tinyhttp import serve, wait_http

SELF_IP = os.environ.get("CS_SELF_IP", "10.200.3.2")
# Bind only on the egress address. 0.0.0.0 on a dual-homed container
# sends UDP replies out the mgmt NIC, which the sandbox cannot see.
HTTP_BIND = os.environ.get("CS_HTTP_BIND", SELF_IP)
DNS_BIND = os.environ.get("CS_DNS_BIND", SELF_IP)
HTTP_PORT = int(os.environ.get("CS_HTTP_PORT", "80"))
DNS_PORT = int(os.environ.get("CS_DNS_PORT", "53"))
LOGGER_HOST = os.environ.get("CS_LOGGER_HOST", "10.200.1.10")
LOGGER_PORT = int(os.environ.get("CS_LOGGER_PORT", "8088"))

HARMLESS_SH = b"#!/bin/sh\necho sinkholed\nexit 0\n"
OK_BODY = b"ok\n"


def parse_name(data: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    jumped = False
    end = offset
    steps = 0
    while steps < 64:
        if offset >= len(data):
            raise ValueError("truncated name")
        length = data[offset]
        if length == 0:
            if not jumped:
                end = offset + 1
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise ValueError("truncated pointer")
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                end = offset + 2
            offset = ptr
            jumped = True
            steps += 1
            continue
        offset += 1
        labels.append(data[offset : offset + length].decode("ascii", errors="replace"))
        offset += length
        steps += 1
    return ".".join(labels), end


def ip_to_bytes(ip: str) -> bytes:
    return socket.inet_aton(ip)


def encode_qname(name: str) -> bytes:
    out = bytearray()
    for label in name.split("."):
        raw = label.encode("ascii")
        out.append(len(raw))
        out.extend(raw)
    out.append(0)
    return bytes(out)


def build_a_response(query: bytes, qname: str, qtype: int, qclass: int, qend: int) -> bytes:
    if len(query) < 12:
        return b""
    txn = query[:2]
    rd = (query[2] & 0x01) << 8  # RD lives in the high flags byte, not RCODE
    # QR | AA | RD(copied) | RA. RCODE must stay 0 — OR-ing RD into the
    # low bit produced FORMERR and musl discarded every answer.
    flags = struct.pack("!H", 0x8480 | rd)
    question = query[12:qend]
    if qtype == 1 and qclass == 1:
        header = txn + flags + struct.pack("!HHHH", 1, 1, 0, 0)
        # Uncompressed name — some stub parsers reject a pointer they cannot chase.
        answer = (
            encode_qname(qname)
            + struct.pack("!HHIH", 1, 1, 30, 4)
            + ip_to_bytes(SELF_IP)
        )
        return header + question + answer
    header = txn + flags + struct.pack("!HHHH", 1, 0, 0, 0)
    return header + question


def emit_dns(src_ip: str, src_port: int, qname: str, qtype: int) -> None:
    event = new_event(
        dataset="cybersnare.sinkhole.dns",
        action="dns-query",
        category=["network"],
        capability="sinkhole",
        source_ip=src_ip,
        source_port=src_port,
        dest_ip=SELF_IP,
        dest_port=DNS_PORT,
        dest_service="dns",
        session_id=str(uuid.uuid4()),
        tactic_id="TA0011",
        tactic_name="Command and Control",
        technique_id="T1071.004",
        technique_name="Application Layer Protocol: DNS",
        extra={"dns": {"question": {"name": qname, "type": qtype}, "stage": 0}},
    )
    emit_bg(event)


class DnsProtocol(asyncio.DatagramProtocol):
    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple) -> None:
        try:
            if len(data) < 12:
                return
            qname, qend = parse_name(data, 12)
            if qend + 4 > len(data):
                return
            qtype, qclass = struct.unpack("!HH", data[qend : qend + 4])
            emit_dns(addr[0], addr[1], qname, qtype)
            resp = build_a_response(data, qname, qtype, qclass, qend + 4)
            if resp:
                self.transport.sendto(resp, addr)
        except Exception as exc:
            print(f"dns error: {exc}", flush=True)


async def http_handler(req: dict) -> tuple[int, dict[str, str], bytes]:
    peer = req.get("peer") or (None, None)
    headers = req.get("headers") or {}
    src_ip = peer[0] if peer else None
    src_port = peer[1] if isinstance(peer, tuple) and len(peer) > 1 else None
    host = headers.get("host")
    path = req.get("path") or "/"
    ua = headers.get("user-agent")
    event = new_event(
        dataset="cybersnare.sinkhole.http",
        action="http-fetch",
        category=["network"],
        capability="sinkhole",
        source_ip=src_ip,
        source_port=src_port,
        dest_ip=SELF_IP,
        dest_port=HTTP_PORT,
        dest_service="http",
        session_id=str(uuid.uuid4()),
        ua_signature=ua,
        extra={
            "url": {"original": f"http://{host}{path}"},
            "http": {"request": {"method": req.get("method"), "path": path}},
            "sinkhole": {"stage": 0, "intended_host": host},
        },
    )
    emit_bg(event)
    if path.endswith(".sh") or path.endswith(".elf") or path.endswith(".bin"):
        return 200, {"Content-Type": "text/plain"}, HARMLESS_SH
    return 200, {"Content-Type": "text/plain"}, OK_BODY


async def main() -> None:
    await wait_http(LOGGER_HOST, LOGGER_PORT, "/health")
    loop = asyncio.get_running_loop()
    await loop.create_datagram_endpoint(
        DnsProtocol, local_addr=(DNS_BIND, DNS_PORT)
    )
    print(f"sinkhole dns on {DNS_BIND}:{DNS_PORT} -> {SELF_IP}", flush=True)
    server = await serve(HTTP_BIND, HTTP_PORT, http_handler, name="sinkhole-http")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
