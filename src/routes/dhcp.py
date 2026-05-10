"""DHCPv4 reservation route — list / create / delete.

Mounted on `/api/plugins/opnsense/api/dhcp`. Refuses writes when plugin
config has read_only=true. Also exposes a subnet-list helper so the UI can
populate the subnet dropdown without re-implementing the search call.
"""
from __future__ import annotations

import logging
import os
from typing import Any

from src.client import (
    OPNsenseAuthError,
    OPNsenseClient,
    OPNsenseError,
    OPNsenseHost,
    OPNsenseTimeoutError,
)
from src.writers import AuditLog, DhcpReservationInput, DhcpReservationWriter

log = logging.getLogger(__name__)


def _audit_log_path(plugin_dir: str) -> str:
    state = os.path.join(plugin_dir, "state")
    os.makedirs(state, exist_ok=True)
    return os.path.join(state, "audit.jsonl")


def build_dhcp_list_payload(host: OPNsenseHost) -> tuple[int, dict[str, Any]]:
    client = OPNsenseClient(host)
    try:
        reservations = client.get("/api/kea/dhcpv4/searchReservation")
        subnets = client.get("/api/kea/dhcpv4/searchSubnet")
        r_rows = reservations.get("rows", []) if isinstance(reservations, dict) else []
        s_rows = subnets.get("rows", []) if isinstance(subnets, dict) else []
        return 200, {"ok": True, "data": {
            "reservations": r_rows,
            "subnets": s_rows,
            "total": len(r_rows),
        }}
    except OPNsenseAuthError as e:
        return 401, {"ok": False, "error": "auth", "detail": str(e)}
    except OPNsenseTimeoutError as e:
        return 504, {"ok": False, "error": "timeout", "detail": str(e)}
    except OPNsenseError as e:
        log.exception("dhcp list failed")
        return 502, {"ok": False, "error": "upstream", "detail": str(e)}


def build_dhcp_action_payload(
    host: OPNsenseHost, plugin_dir: str, body: dict[str, Any],
    actor: str = "plugin", read_only: bool = False,
) -> tuple[int, dict[str, Any]]:
    if read_only:
        return 403, {"ok": False, "error": "read_only", "detail": "plugin config has read_only=true"}
    action = str(body.get("action", "")).lower()
    if action not in ("create", "delete"):
        return 400, {"ok": False, "error": "bad_request", "detail": "action must be create|delete"}

    client = OPNsenseClient(host)
    audit = AuditLog(_audit_log_path(plugin_dir))
    writer = DhcpReservationWriter(client, audit, actor=actor)

    try:
        if action == "create":
            r = body.get("reservation") or {}
            try:
                payload = DhcpReservationInput(
                    subnet=str(r.get("subnet", "")),
                    ip_address=str(r.get("ip_address", "")),
                    hw_address=str(r.get("hw_address", "")),
                    hostname=str(r.get("hostname", "")),
                    description=str(r.get("description", "")),
                )
            except (TypeError, ValueError) as e:
                return 400, {"ok": False, "error": "bad_request", "detail": str(e)}
            try:
                result = writer.create(payload)
            except ValueError as e:
                return 400, {"ok": False, "error": "validation", "detail": str(e)}
        else:
            uuid = str(body.get("uuid", ""))
            if not uuid:
                return 400, {"ok": False, "error": "bad_request", "detail": "uuid is required"}
            result = writer.delete(uuid)
    except OPNsenseAuthError as e:
        return 401, {"ok": False, "error": "auth", "detail": str(e)}
    except OPNsenseTimeoutError as e:
        return 504, {"ok": False, "error": "timeout", "detail": str(e)}
    except OPNsenseError as e:
        log.exception("dhcp action %s failed", action)
        return 502, {"ok": False, "error": "upstream", "detail": str(e)}

    if not result.ok:
        return 502, {"ok": False, "error": "upstream", "detail": result.detail or "write failed"}
    return 200, {"ok": True, "data": {"uuid": result.uuid, "action": action}}
