"""Kea DHCPv4 subnet route — list / create / delete.

Mounted on `/api/plugins/opnsense/api/dhcp_subnet`. Sibling to `/api/dhcp`
(reservations) so the UI can manage subnets without overloading the
reservation create payload.
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
from src.writers import AuditLog, DhcpSubnetInput, DhcpSubnetWriter

log = logging.getLogger(__name__)


def _audit_log_path(plugin_dir: str) -> str:
    state = os.path.join(plugin_dir, "state")
    os.makedirs(state, exist_ok=True)
    return os.path.join(state, "audit.jsonl")


def build_dhcp_subnet_list_payload(host: OPNsenseHost) -> tuple[int, dict[str, Any]]:
    client = OPNsenseClient(host)
    try:
        out = client.get("/api/kea/dhcpv4/searchSubnet")
        rows = out.get("rows", []) if isinstance(out, dict) else []
        return 200, {"ok": True, "data": {"subnets": rows, "total": len(rows)}}
    except OPNsenseAuthError as e:
        return 401, {"ok": False, "error": "auth", "detail": str(e)}
    except OPNsenseTimeoutError as e:
        return 504, {"ok": False, "error": "timeout", "detail": str(e)}
    except OPNsenseError as e:
        log.exception("dhcp subnet list failed")
        return 502, {"ok": False, "error": "upstream", "detail": str(e)}


def build_dhcp_subnet_action_payload(
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
    writer = DhcpSubnetWriter(client, audit, actor=actor)

    try:
        if action == "create":
            s = body.get("subnet") or {}
            try:
                payload = DhcpSubnetInput(
                    subnet=str(s.get("subnet", "")),
                    description=str(s.get("description", "")),
                    pools=str(s.get("pools", "")),
                    next_server=str(s.get("next_server", "")),
                    match_client_id=bool(s.get("match_client_id", True)),
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
        log.exception("dhcp subnet action %s failed", action)
        return 502, {"ok": False, "error": "upstream", "detail": str(e)}

    if not result.ok:
        return 502, {"ok": False, "error": "upstream", "detail": result.detail or "write failed"}
    return 200, {"ok": True, "data": {"uuid": result.uuid, "action": action}}
