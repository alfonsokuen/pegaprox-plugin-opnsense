"""1:1 NAT route — list / create / delete BINAT rules.

Mounted on `/api/plugins/opnsense/api/one_to_one`. Refuses writes when
plugin config has read_only=true.
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
from src.writers import AuditLog, OneToOneNatInput, OneToOneNatWriter

log = logging.getLogger(__name__)


def _audit_log_path(plugin_dir: str) -> str:
    state = os.path.join(plugin_dir, "state")
    os.makedirs(state, exist_ok=True)
    return os.path.join(state, "audit.jsonl")


def build_one_to_one_list_payload(host: OPNsenseHost) -> tuple[int, dict[str, Any]]:
    client = OPNsenseClient(host)
    try:
        out = client.get("/api/firewall/one_to_one/searchRule")
        rows = out.get("rows", []) if isinstance(out, dict) else []
        return 200, {"ok": True, "data": {"rules": rows, "total": len(rows)}}
    except OPNsenseAuthError as e:
        return 401, {"ok": False, "error": "auth", "detail": str(e)}
    except OPNsenseTimeoutError as e:
        return 504, {"ok": False, "error": "timeout", "detail": str(e)}
    except OPNsenseError as e:
        log.exception("one_to_one list failed")
        return 502, {"ok": False, "error": "upstream", "detail": str(e)}


def build_one_to_one_action_payload(
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
    writer = OneToOneNatWriter(client, audit, actor=actor)

    try:
        if action == "create":
            rule = body.get("rule") or {}
            try:
                payload = OneToOneNatInput(
                    interface=str(rule.get("interface", "")),
                    external=str(rule.get("external", "")),
                    source_net=str(rule.get("source_net", "")),
                    destination_net=str(rule.get("destination_net", "any")) or "any",
                    description=str(rule.get("description", "")),
                    enabled=bool(rule.get("enabled", True)),
                    type=str(rule.get("type", "binat")),
                    log=bool(rule.get("log", False)),
                    sequence=str(rule.get("sequence", "100")),
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
        log.exception("one_to_one action %s failed", action)
        return 502, {"ok": False, "error": "upstream", "detail": str(e)}

    if not result.ok:
        return 502, {"ok": False, "error": "upstream", "detail": result.detail or "write failed"}
    return 200, {"ok": True, "data": {"uuid": result.uuid, "action": action}}
