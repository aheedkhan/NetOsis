"""
Actor identity.

The observed source address is the identity. Fingerprints are attributes of it.

An earlier version of this module inverted that, keying actors on HASSH when one
was available and falling back to the address only when it was not, on the
reasoning that a fingerprint survives an address change. It does, but that is
not the property that matters here. HASSH fingerprints the *client software*, so
every operator running the same OpenSSH build produces the same value. Keying on
it merged unrelated actors into a single record: in the lab, a mass scanner and
a hand-driven session originating from two different hosts collapsed into one
actor with one belief state, which made behavioural classification meaningless —
the metronomic evidence from the scanner and the think-time evidence from the
person cancelled each other out.

So identity is the address, and fingerprints do two narrower jobs:

  * they are recorded as attributes, and
  * they link addresses to each other, but only while the fingerprint is rare
    enough to carry information.

A fingerprint seen from many distinct addresses is a common client, not a
signature, and is demoted to an attribute automatically. That threshold is the
whole idea: linkage is only evidence when the thing being shared is unusual.
"""

from __future__ import annotations

import os
from typing import Any

# Above this many distinct source addresses, a fingerprint is treated as a
# common client build and stops linking addresses together. Three is
# deliberately low: the cost of a missed link is one actor recorded twice, and
# the cost of a false link is two actors recorded as one, which is worse
# because it silently corrupts every behavioural signal derived from them.
LINK_MAX_ADDRESSES = int(os.environ.get("CS_LINK_MAX_ADDRESSES", "3"))


def pick_actor_key(
    *,
    hassh: str | None,
    ja4: str | None,
    ip: str | None,
) -> tuple[str, str]:
    """
    Identity key and linkage confidence.

    Confidence describes how much corroborating evidence stands behind the
    identity, not how the key was chosen — the key is the address whenever
    there is one.
    """
    if ip:
        if hassh and ja4:
            return f"ip:{ip}", "high"
        if hassh or ja4:
            return f"ip:{ip}", "medium"
        return f"ip:{ip}", "low"
    # No address at all. Rare, and only from sources that report a fingerprint
    # without a peer address; keyed on the fingerprint so the evidence is not
    # simply discarded.
    if hassh:
        return f"hassh:{hassh}", "low"
    if ja4:
        return f"ja4:{ja4}", "low"
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
    if isinstance(ip, str) and not ip.strip():
        ip = None
    return hassh, ja4, ip


class ActorMap:
    """Address-keyed actor records with fingerprint linkage hints."""

    def __init__(self) -> None:
        self.actors: dict[str, dict[str, Any]] = {}
        # fingerprint -> the set of addresses it has been observed from
        self.hassh_addresses: dict[str, set[str]] = {}
        self.ja4_addresses: dict[str, set[str]] = {}

    # -- linkage -----------------------------------------------------------

    def _record_fingerprint(
        self, hassh: str | None, ja4: str | None, ip: str | None
    ) -> None:
        if not ip:
            return
        if hassh:
            self.hassh_addresses.setdefault(hassh, set()).add(ip)
        if ja4:
            self.ja4_addresses.setdefault(ja4, set()).add(ip)

    def linked_addresses(self, hassh: str | None, ja4: str | None) -> list[str]:
        """
        Other addresses that plausibly belong to the same actor.

        Only fingerprints still below the commonality threshold contribute, so
        a shared OpenSSH build never links two strangers together.
        """
        linked: set[str] = set()
        for value, index in ((hassh, self.hassh_addresses), (ja4, self.ja4_addresses)):
            if not value:
                continue
            addresses = index.get(value) or set()
            if 1 < len(addresses) <= LINK_MAX_ADDRESSES:
                linked |= addresses
        return sorted(linked)

    def fingerprint_is_common(self, hassh: str | None, ja4: str | None) -> bool:
        for value, index in ((hassh, self.hassh_addresses), (ja4, self.ja4_addresses)):
            if value and len(index.get(value) or set()) > LINK_MAX_ADDRESSES:
                return True
        return False

    # -- resolution --------------------------------------------------------

    def resolve(self, event: dict[str, Any]) -> dict[str, Any]:
        hassh, ja4, ip = _fp(event)
        self._record_fingerprint(hassh, ja4, ip)

        actor_key, confidence = pick_actor_key(hassh=hassh, ja4=ja4, ip=ip)
        rec = self.actors.get(actor_key)
        if rec is None:
            rec = {
                "actor_key": actor_key,
                "linked_ips": [ip] if ip else [],
                "hassh": hassh,
                "ja4": ja4,
                "linkage_confidence": confidence,
                "events": 0,
            }
            self.actors[actor_key] = rec

        # Fingerprints accumulate on the record as attributes. The first one
        # seen is kept as primary so the identity does not oscillate when a
        # single actor uses more than one client.
        if hassh and not rec.get("hassh"):
            rec["hassh"] = hassh
        if ja4 and not rec.get("ja4"):
            rec["ja4"] = ja4
        if ip and ip not in rec["linked_ips"]:
            rec["linked_ips"].append(ip)

        rec["linkage_confidence"] = confidence
        related = [a for a in self.linked_addresses(rec.get("hassh"), rec.get("ja4"))
                   if a != ip]
        rec["related_addresses"] = related
        rec["fingerprint_common"] = self.fingerprint_is_common(
            rec.get("hassh"), rec.get("ja4")
        )
        return rec

    # -- reporting ---------------------------------------------------------

    def linkage_report(self) -> list[dict[str, Any]]:
        """Fingerprints and what they currently link, for the analyst view."""
        out: list[dict[str, Any]] = []
        for kind, index in (("hassh", self.hassh_addresses), ("ja4", self.ja4_addresses)):
            for value, addresses in index.items():
                if len(addresses) < 2:
                    continue
                out.append(
                    {
                        "kind": kind,
                        "fingerprint": value,
                        "addresses": sorted(addresses),
                        "links": len(addresses) <= LINK_MAX_ADDRESSES,
                        "reason": (
                            "rare enough to link these addresses"
                            if len(addresses) <= LINK_MAX_ADDRESSES
                            else f"seen from {len(addresses)} addresses — treated as a "
                            f"common client build, not an identity"
                        ),
                    }
                )
        return sorted(out, key=lambda r: -len(r["addresses"]))
