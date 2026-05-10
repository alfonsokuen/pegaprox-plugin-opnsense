"""Interface collector — config + traffic stats per iface."""
from __future__ import annotations

import re
from typing import Any, TypedDict

from src.client import OPNsenseClient


class InterfaceStat(TypedDict):
    name: str            # iface name (e.g. "vtnet0")
    label: str           # OPNsense label ("LAN", "WAN", ...) when known
    macaddr: str
    flags: list[str]
    ipv4: list[dict[str, Any]]
    ipv6: list[dict[str, Any]]
    mtu: int
    received_bytes: int
    sent_bytes: int
    received_packets: int
    sent_packets: int
    received_errors: int
    send_errors: int
    dropped_packets: int
    collisions: int
    is_up: bool


# OPNsense renders the statistics map keys as e.g. "[LAN] (vtnet0) / mac".
_LABEL_RE = re.compile(r"^\[(?P<label>[^\]]+)\]\s+\((?P<name>[^)]+)\)")


def _safe_int(value: Any) -> int:
    try:
        return int(str(value).strip())
    except (ValueError, AttributeError):
        return 0


def _parse_stat_key(key: str) -> tuple[str, str]:
    """Returns (iface_name, friendly_label). Falls back gracefully."""
    m = _LABEL_RE.match(key)
    if m:
        return m["name"], m["label"]
    return key, ""


def collect_interfaces(client: OPNsenseClient) -> list[InterfaceStat]:
    """One snapshot per OPNsense interface (cfg + counters)."""
    cfg = client.get("/api/diagnostics/interface/getInterfaceConfig")
    stats = client.get("/api/diagnostics/interface/getInterfaceStatistics")
    raw_stats = stats.get("statistics", {}) if isinstance(stats, dict) else {}

    by_name: dict[str, dict[str, Any]] = {}
    for k, v in raw_stats.items():
        name, label = _parse_stat_key(k)
        by_name[name] = {**v, "_label": label}

    out: list[InterfaceStat] = []
    if not isinstance(cfg, dict):
        return out

    for name, c in cfg.items():
        s = by_name.get(name, {})
        flags = list(c.get("flags") or [])
        out.append(
            InterfaceStat(
                name=name,
                label=str(s.get("_label", "")),
                macaddr=str(c.get("macaddr", "")),
                flags=flags,
                ipv4=list(c.get("ipv4") or []),
                ipv6=list(c.get("ipv6") or []),
                mtu=_safe_int(s.get("mtu", c.get("mtu", 0))),
                received_bytes=_safe_int(s.get("received-bytes")),
                sent_bytes=_safe_int(s.get("sent-bytes")),
                received_packets=_safe_int(s.get("received-packets")),
                sent_packets=_safe_int(s.get("sent-packets")),
                received_errors=_safe_int(s.get("received-errors")),
                send_errors=_safe_int(s.get("send-errors")),
                dropped_packets=_safe_int(s.get("dropped-packets")),
                collisions=_safe_int(s.get("collisions")),
                is_up=("up" in flags and "running" in flags),
            )
        )
    return out
