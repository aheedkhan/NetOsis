#!/usr/bin/env python3
"""Sample the lab HOST's own CPU/RAM/disk/GPU/temperature and write them to
a JSON file the intelligence service reads and serves at /v1/system.

Deliberately runs on the host, not in a container: the sensor/decision/
deception containers are isolated on purpose (that isolation is the whole
point of the platform), and none of them have — or should have — access to
/dev/nvidia*, lm-sensors, or the host's real disk. This is ops visibility
into the box running the lab, not attacker-facing telemetry, so it stays
outside that boundary entirely and hands the container plane only a small
read-only file to serve.

stdlib only, no pip install needed to run this on a fresh host.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import time
from pathlib import Path

OUT_PATH = Path(os.environ.get("CS_METRICS_OUT", "data/metrics/system.json"))
INTERVAL_S = float(os.environ.get("CS_METRICS_INTERVAL", "2.0"))
DISK_PATH = os.environ.get("CS_METRICS_DISK_PATH", "/")


def _read_proc_stat() -> tuple[int, int]:
    with open("/proc/stat", encoding="utf-8") as fh:
        fields = [int(x) for x in fh.readline().split()[1:]]
    idle = fields[3] + fields[4]  # idle + iowait
    total = sum(fields)
    return idle, total


def cpu_percent(prev: tuple[int, int] | None) -> tuple[float | None, tuple[int, int]]:
    idle, total = _read_proc_stat()
    if prev is None:
        return None, (idle, total)
    d_idle = idle - prev[0]
    d_total = total - prev[1]
    if d_total <= 0:
        return None, (idle, total)
    return round(100.0 * (1 - d_idle / d_total), 1), (idle, total)


def load_avg() -> list[float]:
    with open("/proc/loadavg", encoding="utf-8") as fh:
        return [float(x) for x in fh.read().split()[:3]]


def memory() -> dict:
    fields: dict[str, int] = {}
    with open("/proc/meminfo", encoding="utf-8") as fh:
        for line in fh:
            key, _, rest = line.partition(":")
            fields[key] = int(rest.strip().split()[0])  # kB
    total = fields.get("MemTotal", 0)
    available = fields.get("MemAvailable", 0)
    used = max(total - available, 0)
    return {
        "total_mb": round(total / 1024, 1),
        "used_mb": round(used / 1024, 1),
        "percent": round(100.0 * used / total, 1) if total else None,
    }


def disk() -> dict:
    usage = shutil.disk_usage(DISK_PATH)
    return {
        "path": DISK_PATH,
        "total_gb": round(usage.total / (1024**3), 1),
        "used_gb": round((usage.total - usage.free) / (1024**3), 1),
        "percent": round(100.0 * (usage.total - usage.free) / usage.total, 1) if usage.total else None,
    }


def gpu() -> list[dict] | None:
    try:
        out = subprocess.run(
            [
                "nvidia-smi",
                "--query-gpu=name,utilization.gpu,memory.used,memory.total,temperature.gpu",
                "--format=csv,noheader,nounits",
            ],
            capture_output=True,
            text=True,
            timeout=3,
            check=True,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    gpus = []
    for line in out.strip().splitlines():
        parts = [p.strip() for p in line.split(",")]
        if len(parts) != 5:
            continue
        name, util, mem_used, mem_total, temp = parts
        try:
            gpus.append(
                {
                    "name": name,
                    "util_percent": float(util),
                    "mem_used_mb": float(mem_used),
                    "mem_total_mb": float(mem_total),
                    "temp_c": float(temp),
                }
            )
        except ValueError:
            continue
    return gpus or None


# Prefer a package/CPU-die reading over per-core sensors so the panel shows
# one representative number instead of a noisy per-core list; fall back to
# whatever chip reports first if none of these labels are present.
_PREFERRED_TEMP_LABELS = ("Package id 0", "Tctl", "Tdie", "CPU")


def temperatures() -> list[dict] | None:
    try:
        out = subprocess.run(
            ["sensors", "-j"], capture_output=True, text=True, timeout=3, check=True
        ).stdout
        data = json.loads(out)
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        return _temperatures_from_thermal_zones()
    readings: list[dict] = []
    for chip, fields in data.items():
        if not isinstance(fields, dict):
            continue
        for label, values in fields.items():
            if not isinstance(values, dict):
                continue
            temp_key = next((k for k in values if k.startswith("temp") and k.endswith("_input")), None)
            if not temp_key:
                continue
            readings.append({"label": label, "chip": chip, "temp_c": round(values[temp_key], 1)})
    if not readings:
        return _temperatures_from_thermal_zones()
    readings.sort(key=lambda r: (r["label"] not in _PREFERRED_TEMP_LABELS, r["label"]))
    return readings[:8]


def _temperatures_from_thermal_zones() -> list[dict] | None:
    base = Path("/sys/class/thermal")
    if not base.is_dir():
        return None
    readings = []
    for zone in sorted(base.glob("thermal_zone*")):
        try:
            zone_type = (zone / "type").read_text().strip()
            millideg = int((zone / "temp").read_text().strip())
        except (OSError, ValueError):
            continue
        readings.append({"label": zone_type, "chip": "thermal_zone", "temp_c": round(millideg / 1000, 1)})
    return readings[:8] or None


def sample(prev_cpu: tuple[int, int] | None) -> tuple[dict, tuple[int, int]]:
    cpu_pct, next_cpu = cpu_percent(prev_cpu)
    with open("/proc/uptime", encoding="utf-8") as fh:
        uptime_s = float(fh.read().split()[0])
    return (
        {
            "timestamp": time.time(),
            "hostname": socket.gethostname(),
            "uptime_s": round(uptime_s),
            "cpu": {
                "percent": cpu_pct,
                "cores": os.cpu_count(),
                "load_avg": load_avg(),
            },
            "memory": memory(),
            "disk": disk(),
            "gpu": gpu(),
            "temperatures": temperatures(),
        },
        next_cpu,
    )


def write_atomic(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload, separators=(",", ":")))
    os.replace(tmp, path)


def main() -> None:
    prev_cpu: tuple[int, int] | None = None
    while True:
        try:
            payload, prev_cpu = sample(prev_cpu)
            write_atomic(OUT_PATH, payload)
        except Exception as exc:  # keep sampling even if one metric source misbehaves
            print(f"host-metrics: sample failed: {exc}", flush=True)
        time.sleep(INTERVAL_S)


if __name__ == "__main__":
    main()
