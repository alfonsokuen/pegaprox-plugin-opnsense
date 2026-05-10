"""System-level collector — version, resources, time, pf state."""
from __future__ import annotations

from typing import Any, TypedDict

from src.client import OPNsenseClient


class SystemSnapshot(TypedDict, total=False):
    name: str
    versions: list[str]
    cpu_type: str
    uptime: str
    boottime: str
    config_change: str
    loadavg: list[float]
    memory_total_mb: int
    memory_used_mb: int
    memory_used_pct: float
    arc_mb: int
    pf_states_current: int
    pf_states_limit: int
    pf_states_pct: float


def _to_int(value: Any) -> int:
    """OPNsense returns numeric fields as strings — coerce safely."""
    try:
        return int(str(value).strip())
    except (ValueError, AttributeError):
        return 0


def _parse_loadavg(text: str) -> list[float]:
    out: list[float] = []
    for chunk in (text or "").split(","):
        try:
            out.append(float(chunk.strip()))
        except ValueError:
            continue
    return out


def collect_system(client: OPNsenseClient) -> SystemSnapshot:
    """Aggregated overview of the OPNsense node.

    Issues 4 cheap GETs + 1 pf_states call. Safe for the fast (5s) tick.
    """
    info = client.get("/api/diagnostics/system/system_information")
    res = client.get("/api/diagnostics/system/systemResources")
    when = client.get("/api/diagnostics/system/systemTime")
    pf = client.get("/api/diagnostics/firewall/pf_states")

    cpu_types: list[str] = []
    try:
        cpu_types = client.get("/api/diagnostics/cpu_usage/getCPUType")  # type: ignore[assignment]
    except Exception:  # pragma: no cover - lab quirk; non-critical
        cpu_types = []

    mem = res.get("memory", {}) if isinstance(res, dict) else {}
    total_mb = _to_int(mem.get("total_frmt"))
    used_mb = _to_int(mem.get("used_frmt"))
    pct = (used_mb / total_mb * 100) if total_mb else 0.0
    arc_mb = _to_int(mem.get("arc_frmt"))

    pf_cur = _to_int(pf.get("current"))
    pf_lim = _to_int(pf.get("limit"))
    pf_pct = (pf_cur / pf_lim * 100) if pf_lim else 0.0

    snap: SystemSnapshot = {
        "name": str(info.get("name", "")),
        "versions": list(info.get("versions") or []),
        "cpu_type": cpu_types[0] if cpu_types else "",
        "uptime": str(when.get("uptime", "")),
        "boottime": str(when.get("boottime", "")),
        "config_change": str(when.get("config", "")),
        "loadavg": _parse_loadavg(when.get("loadavg", "")),
        "memory_total_mb": total_mb,
        "memory_used_mb": used_mb,
        "memory_used_pct": round(pct, 2),
        "arc_mb": arc_mb,
        "pf_states_current": pf_cur,
        "pf_states_limit": pf_lim,
        "pf_states_pct": round(pf_pct, 4),
    }
    return snap
