"""VPN collectors — WireGuard / IPsec / OpenVPN session views."""
from __future__ import annotations

from typing import Any, TypedDict

from src.client import OPNsenseClient


class VPNPeer(TypedDict):
    type: str            # "wireguard" | "ipsec" | "openvpn"
    name: str            # peer/tunnel friendly name
    enabled: bool
    connected: bool
    remote_address: str  # remote endpoint or assigned IP if available
    raw: dict[str, Any]  # untouched OPNsense row, for the UI to reach into


class VPNSnapshot(TypedDict):
    wireguard_enabled: bool
    wireguard_peers: list[VPNPeer]
    ipsec_phase1: list[VPNPeer]
    openvpn_sessions: list[VPNPeer]


def _bool01(value: Any) -> bool:
    try:
        return int(str(value).strip()) == 1
    except (ValueError, AttributeError):
        return False


def _peer(kind: str, row: dict[str, Any], name_keys: tuple[str, ...], remote_keys: tuple[str, ...]) -> VPNPeer:
    name = next((str(row[k]) for k in name_keys if row.get(k)), "")
    remote = next((str(row[k]) for k in remote_keys if row.get(k)), "")
    enabled_raw = row.get("enabled", row.get("status", ""))
    return VPNPeer(
        type=kind,
        name=name,
        enabled=_bool01(enabled_raw) or str(enabled_raw).lower() in ("true", "yes"),
        connected=_bool01(row.get("connected", row.get("running", ""))),
        remote_address=remote,
        raw=row,
    )


def collect_wireguard(client: OPNsenseClient) -> tuple[bool, list[VPNPeer]]:
    """Returns (service_enabled, peers)."""
    general = client.get("/api/wireguard/general/get")
    enabled = _bool01(
        ((general or {}).get("general", {}) or {}).get("enabled", 0)
    )
    show = client.get("/api/wireguard/service/show")
    rows = show.get("rows", []) if isinstance(show, dict) else []
    peers = [
        _peer("wireguard", r, ("name", "instance"), ("endpoint", "endpoint_address"))
        for r in rows
    ]
    return enabled, peers


def collect_ipsec(client: OPNsenseClient) -> list[VPNPeer]:
    """Phase 1 sessions. Phase 2 is a separate call kept for writers."""
    payload = client.get("/api/ipsec/sessions/searchPhase1")
    rows = payload.get("rows", []) if isinstance(payload, dict) else []
    return [_peer("ipsec", r, ("name", "id"), ("remote-host", "remote_addr")) for r in rows]


def collect_openvpn(client: OPNsenseClient) -> list[VPNPeer]:
    payload = client.get("/api/openvpn/service/searchSessions")
    rows = payload.get("rows", []) if isinstance(payload, dict) else []
    return [
        _peer("openvpn", r, ("description", "common_name", "id"), ("real_address", "virtual_addr"))
        for r in rows
    ]


def collect_vpn(client: OPNsenseClient) -> VPNSnapshot:
    wg_enabled, wg_peers = collect_wireguard(client)
    return VPNSnapshot(
        wireguard_enabled=wg_enabled,
        wireguard_peers=wg_peers,
        ipsec_phase1=collect_ipsec(client),
        openvpn_sessions=collect_openvpn(client),
    )
