"""CARP role + VIP snapshot.

OPNsense 26.x does NOT expose a separate `/api/diagnostics/interface/getCarpStatus`
endpoint (live probe vs prod NODOA/NODOB 2026-05-11: returns 404 "Endpoint not
found"). Service-level CARP state lives inside `getVipStatus`'s `carp` block
(maintenancemode + demotion + status_msg). The CARP VIPs themselves come from
the `rows` array of that same response.

Node-level `role` resolution rules:
  1. No active CARP VIPs (or all DISABLED) → `disabled`.
  2. Maintenance mode flag set → `backup` (regardless of VIP states).
  3. If a single "primary" VIP can be identified (lowest advskew on the
     lowest VHID) → its status drives the node role.
  4. Otherwise: majority of active VIPs (ties favour MASTER for visibility,
     since a single MASTER VIP on a node is operationally significant).

Exposes per-VHID rows plus `demotion` and `status_msg` so the UI can surface
the demote message that OPNsense emits when a node is operationally degraded.
"""
from __future__ import annotations

from typing import Any, Literal, TypedDict

from src.client import OPNsenseClient, OPNsenseError

CarpRole = Literal["master", "backup", "disabled", "unknown"]


class CarpVhid(TypedDict):
    vhid: str
    interface: str
    ipaddr: str
    status: str          # MASTER | BACKUP | INIT | DISABLED
    advbase: str
    advskew: str


class CarpStatus(TypedDict):
    role: CarpRole
    enabled: bool
    maintenance_mode: bool
    demotion: int
    status_msg: str
    vhids: list[CarpVhid]


def _bool_truthy(value: Any) -> bool:
    """Accepts JSON true, "1", 1, True. Reject "0", 0, false, None."""
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    try:
        return int(str(value).strip()) == 1
    except (ValueError, AttributeError):
        return str(value).strip().lower() == "true"


def _safe_get(client: OPNsenseClient, path: str) -> dict[str, Any]:
    try:
        result = client.get(path)
        return result if isinstance(result, dict) else {}
    except OPNsenseError:
        return {}


def _primary_vhid(vhids: list[CarpVhid]) -> CarpVhid | None:
    """The 'primary' VIP for node-role purposes — lowest VHID, lowest advskew
    among the active (non-DISABLED) ones."""
    active = [v for v in vhids if v["status"] not in ("DISABLED", "")]
    if not active:
        return None
    return sorted(
        active,
        key=lambda v: (int(v["vhid"] or 9999), int(v["advskew"] or 9999)),
    )[0]


def _classify_role(enabled: bool, maintenance: bool, vhids: list[CarpVhid]) -> CarpRole:
    if not enabled:
        return "disabled"
    if maintenance:
        return "backup"
    primary = _primary_vhid(vhids)
    if primary is None:
        # All vhids DISABLED but CARP service is on — treat as disabled.
        return "disabled"
    status = primary["status"]
    if status == "MASTER":
        return "master"
    if status == "BACKUP":
        return "backup"
    return "unknown"


def collect_carp_status(client: OPNsenseClient) -> CarpStatus:
    vip = _safe_get(client, "/api/diagnostics/interface/getVipStatus")
    rows_raw = vip.get("rows", []) if isinstance(vip.get("rows"), list) else []
    carp_blk = vip.get("carp", {}) if isinstance(vip.get("carp"), dict) else {}

    vhids: list[CarpVhid] = []
    for r in rows_raw:
        if not isinstance(r, dict):
            continue
        # Only CARP-type VIPs; getVipStatus also lists alias/proxyarp rows.
        if str(r.get("mode", "carp")).lower() != "carp":
            continue
        vhids.append(CarpVhid(
            vhid=str(r.get("vhid", "")),
            interface=str(r.get("interface", "")),
            ipaddr=str(r.get("ipaddr", r.get("subnet", ""))),
            status=str(r.get("status", "")).upper(),
            advbase=str(r.get("advbase", "")),
            advskew=str(r.get("advskew", "")),
        ))

    maintenance = _bool_truthy(carp_blk.get("maintenancemode", carp_blk.get("maintenance_mode", False)))

    # `enabled` = the CARP service has at least one configured VIP (DISABLED-state
    # VIPs still count as configured; the service is running, the VIPs are just
    # administratively disabled). When zero CARP rows came back, treat the
    # service as off.
    enabled = bool(vhids)

    # demotion is negative when CARP detects a problem (link down, etc.)
    try:
        demotion = int(carp_blk.get("demotion", 0))
    except (TypeError, ValueError):
        demotion = 0

    status_msg = str(carp_blk.get("status_msg", ""))

    return CarpStatus(
        role=_classify_role(enabled, maintenance, vhids),
        enabled=enabled,
        maintenance_mode=maintenance,
        demotion=demotion,
        status_msg=status_msg,
        vhids=vhids,
    )
