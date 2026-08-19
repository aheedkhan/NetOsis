"""Actor linkage v0: fingerprints beat addresses. Decision plane owns this map."""

from __future__ import annotations

from typing import Any


def pick_actor_key(
    *,
    hassh: str | None,
    ja4: str | None,
    ip: str | None,
) -> tuple[str, str]:
    if hassh:
        return f"hassh:{hassh}", "high"
    if ja4:
        return f"ja4:{ja4}", "medium"
    if ip:
        return f"ip:{ip}", "low"
    return "actor:unknown", "none"


def _fp(event: dict[str, Any]) -> tuple[str | None, str | None, str | None]:
    net = event.get("network") or {}
    src = event.get("source") or {}
    hassh = net.get("hassh") or None
    ja4 = net.get("ja4") or None
    ip = src.get("ip") or None
    if isinstance(hassh, str) and not hassh.strip():
        hassh = None
    if isinstance(ja4, str) and not ja4.strip():
        ja4 = None
    return hassh, ja4, ip


class ActorMap:
    def __init__(self) -> None:
        self.actors: dict[str, dict[str, Any]] = {}
        self.by_hassh: dict[str, str] = {}
        self.by_ja4: dict[str, str] = {}
        self.by_ip: dict[str, str] = {}

    def resolve(self, event: dict[str, Any]) -> dict[str, Any]:
        hassh, ja4, ip = _fp(event)
        found: list[str] = []
        for key in (
            self.by_hassh.get(hassh) if hassh else None,
            self.by_ja4.get(ja4) if ja4 else None,
            self.by_ip.get(ip) if ip else None,
        ):
            if key and key in self.actors and key not in found:
                found.append(key)

        if not found:
            actor_key, confidence = pick_actor_key(hassh=hassh, ja4=ja4, ip=ip)
            rec = {
                "actor_key": actor_key,
                "linked_ips": [ip] if ip else [],
                "hassh": hassh,
                "ja4": ja4,
                "linkage_confidence": confidence,
                "events": 0,
            }
            self.actors[actor_key] = rec
            self._index(rec)
            return rec

        canonical = found[0]
        for other in found[1:]:
            self._merge(canonical, other)
            canonical = self.by_hassh.get(hassh) or self.by_ja4.get(ja4) or canonical
        rec = self.actors.get(canonical) or self.actors[found[0]]
        if hassh:
            rec["hassh"] = hassh
        if ja4:
            rec["ja4"] = rec.get("ja4") or ja4
        if ip and ip not in rec["linked_ips"]:
            rec["linked_ips"].append(ip)
        new_key, conf = pick_actor_key(
            hassh=rec.get("hassh"), ja4=rec.get("ja4"), ip=ip
        )
        rec["linkage_confidence"] = conf
        old_key = rec["actor_key"]
        if new_key != old_key:
            rec["actor_key"] = new_key
            self.actors.pop(old_key, None)
            self.actors[new_key] = rec
        self._index(rec)
        return rec

    def _index(self, rec: dict[str, Any]) -> None:
        key = rec["actor_key"]
        if rec.get("hassh"):
            self.by_hassh[rec["hassh"]] = key
        if rec.get("ja4"):
            self.by_ja4[rec["ja4"]] = key
        for ip in rec.get("linked_ips") or []:
            if ip:
                self.by_ip[ip] = key

    def _merge(self, canonical_key: str, other_key: str) -> None:
        if canonical_key == other_key or other_key not in self.actors:
            return
        dst = self.actors[canonical_key]
        src = self.actors.pop(other_key)
        for ip in src.get("linked_ips") or []:
            if ip and ip not in dst["linked_ips"]:
                dst["linked_ips"].append(ip)
        dst["hassh"] = dst.get("hassh") or src.get("hassh")
        dst["ja4"] = dst.get("ja4") or src.get("ja4")
        dst["events"] = int(dst.get("events") or 0) + int(src.get("events") or 0)
        if dst.get("hassh"):
            dst["actor_key"] = f"hassh:{dst['hassh']}"
            dst["linkage_confidence"] = "high"
        elif dst.get("ja4"):
            dst["actor_key"] = f"ja4:{dst['ja4']}"
            dst["linkage_confidence"] = "medium"
        if dst["actor_key"] != canonical_key:
            self.actors.pop(canonical_key, None)
            self.actors[dst["actor_key"]] = dst
        self._index(dst)
