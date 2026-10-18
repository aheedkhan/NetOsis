"""IP -> approximate location, honest by construction.

Rules (from docs/NETOSIS_UI_RESOURCES.md "Data integrity rules"):
  * Private, loopback, link-local, CGNAT, documentation and other reserved
    addresses are NEVER geolocated. The lab's own attackers (Kali on
    172.30.227.0/24) are shown as "Lab / internal", not as a country.
  * Public addresses are looked up only if a MaxMind GeoLite2 database is
    present (data/geoip/GeoLite2-City.mmdb or -Country.mmdb) and the optional
    `maxminddb` package is installed. No database -> "unmapped", never a guess.
  * Demo fixtures (scripts/soc_demo.py) use RFC 5737 documentation addresses,
    which no lookup can resolve. They get illustrative locations from
    DEMO_FIXTURES below and are flagged `source="demo"` so the UI labels them.
  * An IP location is the network's registered/approximate location, not the
    attacker's verified physical location. Every result says how it was obtained.

The destination of every arc is this lab, whose location only the operator
knows: NETOSIS_SITE_LAT / NETOSIS_SITE_LNG / NETOSIS_SITE_LABEL in
controller/.env. Unset -> no live arcs are drawn (the UI explains why).
"""

from __future__ import annotations

import hashlib
import ipaddress
import os
from functools import lru_cache
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]

# Illustrative only. Documentation ranges (RFC 5737) so nothing here can be
# mistaken for, or slander, a real network.
DEMO_FIXTURES: dict[str, dict[str, Any]] = {
    "203.0.113.24": {"country": "Netherlands", "iso": "NL", "city": "Amsterdam", "lat": 52.37, "lng": 4.90},
    "198.51.100.77": {"country": "Brazil", "iso": "BR", "city": "São Paulo", "lat": -23.55, "lng": -46.63},
    "192.0.2.140": {"country": "Singapore", "iso": "SG", "city": "Singapore", "lat": 1.35, "lng": 103.82},
    "203.0.113.201": {"country": "United States", "iso": "US", "city": "Ashburn", "lat": 39.04, "lng": -77.49},
}
DEMO_SITE = {"label": "NetOsis lab (demo location)", "lat": 33.68, "lng": 73.05}
# Extra illustrative cities for the demo's randomised documentation addresses.
DEMO_CITIES: list[dict[str, Any]] = [
    {"country": "Germany", "iso": "DE", "city": "Frankfurt", "lat": 50.11, "lng": 8.68},
    {"country": "Russia", "iso": "RU", "city": "Moscow", "lat": 55.76, "lng": 37.62},
    {"country": "China", "iso": "CN", "city": "Shanghai", "lat": 31.23, "lng": 121.47},
    {"country": "Vietnam", "iso": "VN", "city": "Hanoi", "lat": 21.03, "lng": 105.85},
    {"country": "India", "iso": "IN", "city": "Mumbai", "lat": 19.08, "lng": 72.88},
    {"country": "Iran", "iso": "IR", "city": "Tehran", "lat": 35.69, "lng": 51.39},
    {"country": "South Africa", "iso": "ZA", "city": "Johannesburg", "lat": -26.20, "lng": 28.05},
    {"country": "United Kingdom", "iso": "GB", "city": "London", "lat": 51.51, "lng": -0.13},
    {"country": "Canada", "iso": "CA", "city": "Toronto", "lat": 43.65, "lng": -79.38},
    {"country": "Mexico", "iso": "MX", "city": "Mexico City", "lat": 19.43, "lng": -99.13},
    {"country": "Japan", "iso": "JP", "city": "Tokyo", "lat": 35.68, "lng": 139.69},
    {"country": "Australia", "iso": "AU", "city": "Sydney", "lat": -33.87, "lng": 151.21},
]

_CGNAT = ipaddress.ip_network("100.64.0.0/10")


def classify(ip: str) -> str:
    """'public' | 'private' | 'reserved' | 'invalid'."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "invalid"
    if addr.version == 4 and addr in _CGNAT:
        return "private"
    if addr.is_private or addr.is_loopback or addr.is_link_local:
        # Python counts RFC 5737 documentation ranges as private too.
        if any(addr in ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")):
            return "reserved"
        return "private"
    if addr.is_reserved or addr.is_multicast or addr.is_unspecified:
        return "reserved"
    return "public"


@lru_cache(maxsize=1)
def _reader():
    for name in ("GeoLite2-City.mmdb", "GeoLite2-Country.mmdb"):
        path = Path(os.environ.get("NETOSIS_GEOIP_DIR", ROOT / "data" / "geoip")) / name
        if path.is_file():
            try:
                import maxminddb  # optional dependency

                return maxminddb.open_database(str(path)), name
            except Exception:
                return None
    return None


def geodb_status() -> dict[str, Any]:
    r = _reader()
    return {"available": r is not None, "database": r[1] if r else None}


def locate(ip: str, *, demo: bool = False) -> dict[str, Any]:
    kind = classify(ip)
    base: dict[str, Any] = {"ip": ip, "kind": kind, "mapped": False, "source": None}
    if demo and ip in DEMO_FIXTURES:
        return {**base, **DEMO_FIXTURES[ip], "mapped": True, "source": "demo", "approximate": True}
    if demo and kind == "reserved":
        city = DEMO_CITIES[int(hashlib.sha256(ip.encode()).hexdigest()[:8], 16) % len(DEMO_CITIES)]
        return {**base, **city, "mapped": True, "source": "demo", "approximate": True}
    if kind == "private":
        return {**base, "label": "Lab / internal network"}
    if kind != "public":
        return {**base, "label": "Reserved address"}
    r = _reader()
    if r is None:
        return {**base, "label": "Public, not geolocated (no GeoIP database)"}
    try:
        rec = r[0].get(ip) or {}
    except Exception:
        rec = {}
    loc = rec.get("location") or {}
    country = rec.get("country") or rec.get("registered_country") or {}
    if loc.get("latitude") is None:
        return {**base, "label": "Public, location unknown", "country": (country.get("names") or {}).get("en")}
    return {
        **base,
        "mapped": True,
        "source": r[1],
        "approximate": True,
        "accuracy_km": loc.get("accuracy_radius"),
        "country": (country.get("names") or {}).get("en"),
        "iso": country.get("iso_code"),
        "city": ((rec.get("city") or {}).get("names") or {}).get("en"),
        "lat": loc["latitude"],
        "lng": loc["longitude"],
    }


def site(*, demo: bool = False) -> dict[str, Any] | None:
    try:
        lat = float(os.environ["NETOSIS_SITE_LAT"])
        lng = float(os.environ["NETOSIS_SITE_LNG"])
        return {"label": os.environ.get("NETOSIS_SITE_LABEL", "NetOsis lab"), "lat": lat, "lng": lng, "source": "config"}
    except (KeyError, ValueError):
        return {**DEMO_SITE, "source": "demo"} if demo else None
