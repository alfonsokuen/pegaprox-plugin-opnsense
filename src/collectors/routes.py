"""System routes + ARP/NDP neighbor tables."""
from __future__ import annotations

from typing import TypedDict

from src.client import OPNsenseClient


class Route(TypedDict):
    proto: str           # "ipv4" | "ipv6"
    destination: str     # "default" or CIDR
    gateway: str
    flags: str
    netif: str
    interface: str       # OPNsense friendly description (intf_description)
    mtu: int
    expire: str


class Neighbor(TypedDict):
    ip: str
    mac: str
    interface: str
    interface_name: str  # raw netif (e.g. "vtnet0")
    permanent: bool
    expired: bool
    manufacturer: str
    hostname: str
    family: str          # "ipv4" | "ipv6"


def _safe_int(value: object) -> int:
    try:
        return int(str(value).strip())
    except (ValueError, AttributeError):
        return 0


def collect_routes(client: OPNsenseClient) -> list[Route]:
    rows = client.get("/api/diagnostics/interface/getRoutes")
    out: list[Route] = []
    if not isinstance(rows, list):
        return out
    for r in rows:
        out.append(
            Route(
                proto=str(r.get("proto", "")),
                destination=str(r.get("destination", "")),
                gateway=str(r.get("gateway", "")),
                flags=str(r.get("flags", "")),
                netif=str(r.get("netif", "")),
                interface=str(r.get("intf_description", "")),
                mtu=_safe_int(r.get("mtu", 0)),
                expire=str(r.get("expire", "")),
            )
        )
    return out


def _neighbor(r: dict, family: str) -> Neighbor:
    return Neighbor(
        ip=str(r.get("ip", "")),
        mac=str(r.get("mac", "")),
        interface=str(r.get("intf_description", "")),
        interface_name=str(r.get("intf", "")),
        permanent=bool(r.get("permanent", False)),
        expired=bool(r.get("expired", False)),
        manufacturer=str(r.get("manufacturer", "")),
        hostname=str(r.get("hostname", "")),
        family=family,
    )


def collect_arp(client: OPNsenseClient) -> list[Neighbor]:
    rows = client.get("/api/diagnostics/interface/getArp")
    return [_neighbor(r, "ipv4") for r in rows] if isinstance(rows, list) else []


def collect_ndp(client: OPNsenseClient) -> list[Neighbor]:
    rows = client.get("/api/diagnostics/interface/getNdp")
    return [_neighbor(r, "ipv6") for r in rows] if isinstance(rows, list) else []
