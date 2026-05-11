"""CARP role + VIP snapshot.

Reads `/api/diagnostics/interface/getCarpStatus` for the service-level role
(maintenance mode toggle) and `/api/diagnostics/interface/getVipStatus` for
per-VHID state (MASTER/BACKUP/INIT, advbase/advskew). Resolves a node-level
`role` by majority: if ANY non-disabled vhid is BACKUP and CARP is enabled,
the node is "backup"; if all CARP vhids are MASTER, "master"; otherwise
"unknown" or "disabled".

Tolerant of both endpoints being missing — older OPNsense or non-CARP
deployments return 404/empty. In those cases role="disabled" and vhids=[].
"""
from __future__ import annotations

from typing import Any, Literal, TypedDict

from src.client import OPNsenseClient, OPNsenseError

CarpRole = Literal["master", "backup", "disabled", "unknown"]


class CarpVhid(TypedDict):
    vhid: str
    interface: str
    ipaddr: str
    status: str          # raw OPNsense status: MASTER | BACKUP | INIT | DISABLED
    advbase: str
    advskew: str


class CarpStatus(TypedDict):
    role: CarpRole
    enabled: bool
    maintenance_mode: bool
    vhids: list[CarpVhid]


def _bool01(value: Any) -> bool:
    try:
        return int(str(value).strip()) == 1
    except (ValueError, AttributeError):
        return False


def _safe_get(client: OPNsenseClient, path: str) -> dict[str, Any]:
    try:
        result = client.get(path)
        return result if isinstance(result, dict) else {}
    except OPNsenseError:
        return {}


def _classify_role(enabled: bool, maintenance: bool, vhids: list[CarpVhid]) -> CarpRole:
    if not enabled:
        return "disabled"
    if maintenance:
        return "backup"  # maintenance forces backup
    active = [v for v in vhids if v["status"] not in ("DISABLED", "")]
    if not active:
        return "unknown"
    if all(v["status"] == "MASTER" for v in active):
        return "master"
    if all(v["status"] == "BACKUP" for v in active):
        return "backup"
    # split-brain or transitional INIT — surface as unknown so divergence flags it
    return "unknown"


def collect_carp_status(client: OPNsenseClient) -> CarpStatus:
    svc = _safe_get(client, "/api/diagnostics/interface/getCarpStatus")
    enabled = _bool01(svc.get("carp_enabled", svc.get("carp", 0)))
    maintenance = _bool01(svc.get("maintenance_mode", 0))

    vip = _safe_get(client, "/api/diagnostics/interface/getVipStatus")
    rows = vip.get("rows", []) if isinstance(vip.get("rows"), list) else []
    vhids: list[CarpVhid] = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        # Filter to CARP-type VIPs; OPNsense getVipStatus also returns alias/proxyarp rows.
        mode = str(r.get("mode", "carp")).lower()
        if mode and mode != "carp":
            continue
        vhids.append(CarpVhid(
            vhid=str(r.get("vhid", "")),
            interface=str(r.get("interface", "")),
            ipaddr=str(r.get("ipaddr", r.get("subnet", ""))),
            status=str(r.get("status", "")).upper(),
            advbase=str(r.get("advbase", "")),
            advskew=str(r.get("advskew", "")),
        ))

    return CarpStatus(
        role=_classify_role(enabled, maintenance, vhids),
        enabled=enabled,
        maintenance_mode=maintenance,
        vhids=vhids,
    )
