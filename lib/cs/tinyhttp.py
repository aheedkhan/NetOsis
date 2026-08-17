"""Minimal asyncio HTTP/1.1 server and client. Stdlib only."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable
from typing import Any

Handler = Callable[[dict[str, Any]], Awaitable[tuple[int, dict[str, str], bytes]]]


def _http_date() -> str:
    from email.utils import formatdate

    return formatdate(usegmt=True)


async def read_request(
    reader: asyncio.StreamReader, limit: int = 1_048_576
) -> dict[str, Any]:
    line = await asyncio.wait_for(reader.readline(), timeout=10)
    if not line:
        raise ConnectionError("empty")
    parts = line.decode("iso-8859-1").rstrip("\r\n").split(" ")
    if len(parts) < 2:
        raise ValueError("bad request line")
    method, raw_path = parts[0].upper(), parts[1]
    path, _, query = raw_path.partition("?")
    headers: dict[str, str] = {}
    header_order: list[str] = []
    while True:
        hline = await asyncio.wait_for(reader.readline(), timeout=10)
        if hline in (b"\r\n", b"\n", b""):
            break
        decoded = hline.decode("iso-8859-1").rstrip("\r\n")
        name, _, value = decoded.partition(":")
        key = name.strip().lower()
        headers[key] = value.strip()
        header_order.append(name.strip())
    length = int(headers.get("content-length", "0") or "0")
    if length > limit:
        raise ValueError("body too large")
    body = b""
    if length:
        body = await asyncio.wait_for(reader.readexactly(length), timeout=10)
    return {
        "method": method,
        "path": path,
        "query": query,
        "headers": headers,
        "header_order": header_order,
        "body": body,
    }


async def write_response(
    writer: asyncio.StreamWriter,
    status: int,
    headers: dict[str, str],
    body: bytes,
) -> None:
    reason = {
        200: "OK",
        204: "No Content",
        400: "Bad Request",
        401: "Unauthorized",
        404: "Not Found",
        413: "Payload Too Large",
        500: "Internal Server Error",
        503: "Service Unavailable",
    }.get(status, "OK")
    hdrs = {
        "Date": _http_date(),
        "Connection": "close",
        "Content-Length": str(len(body)),
        **headers,
    }
    out = [f"HTTP/1.1 {status} {reason}\r\n"]
    for k, v in hdrs.items():
        out.append(f"{k}: {v}\r\n")
    out.append("\r\n")
    writer.write("".join(out).encode("iso-8859-1") + body)
    await writer.drain()


def json_body(req: dict[str, Any]) -> Any:
    if not req["body"]:
        return None
    return json.loads(req["body"].decode("utf-8"))


async def serve(
    host: str,
    port: int,
    handler: Handler,
    *,
    name: str = "http",
) -> asyncio.AbstractServer:
    async def _client(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peer = writer.get_extra_info("peername")
        try:
            req = await read_request(reader)
            req["peer"] = peer
            status, headers, body = await handler(req)
            await write_response(writer, status, headers, body)
        except asyncio.TimeoutError:
            try:
                await write_response(
                    writer, 400, {"Content-Type": "text/plain"}, b"timeout\n"
                )
            except Exception:
                pass
        except Exception as exc:
            try:
                msg = f"{type(exc).__name__}\n".encode()
                await write_response(
                    writer, 400, {"Content-Type": "text/plain"}, msg
                )
            except Exception:
                pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    server = await asyncio.start_server(_client, host, port)
    print(f"{name} listening on {host}:{port}", flush=True)
    return server


async def post_json(
    host: str,
    port: int,
    path: str,
    payload: Any,
    *,
    timeout: float = 0.4,
) -> int:
    body = json.dumps(payload, separators=(",", ":")).encode()
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port), timeout=timeout
    )
    try:
        req = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            "Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n"
            "\r\n"
        )
        writer.write(req.encode("iso-8859-1") + body)
        await writer.drain()
        line = await asyncio.wait_for(reader.readline(), timeout=timeout)
        parts = line.decode("iso-8859-1").split(" ")
        return int(parts[1]) if len(parts) > 1 else 0
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def wait_http(host: str, port: int, path: str = "/health", timeout: float = 30) -> None:
    deadline = asyncio.get_event_loop().time() + timeout
    last = None
    while asyncio.get_event_loop().time() < deadline:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=1.0
            )
            writer.write(
                f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()
            )
            await writer.drain()
            line = await reader.readline()
            writer.close()
            await writer.wait_closed()
            if line.startswith(b"HTTP/1.1 2"):
                return
            last = line
        except Exception as exc:
            last = exc
        await asyncio.sleep(0.2)
    raise TimeoutError(f"timeout waiting for http://{host}:{port}{path}: {last}")
