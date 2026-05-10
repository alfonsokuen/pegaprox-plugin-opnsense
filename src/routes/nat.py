"""NAT endpoint — list source NAT rules + create + delete.

Mounted on `/api/plugins/opnsense/api/nat`.

Methods:
  GET  → list outbound NAT rules
  POST {action: "create", rule: {...}}  → add + apply
  POST {action: "delete", uuid: "..."}  → remove + apply

Refuses writes when the plugin config is set to read_only.
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
from src.writers import AuditLog, NatInput, NatWriter

log = logging.getLogger(__name__)


def _audit_log_path(plugin_dir: str) -> str:
    state = os.path.join(plugin_dir, "state")
    os.makedirs(state, exist_ok=True)
    return os.path.join(state, "audit.jsonl")


def build_nat_list_payload(host: OPNsenseHost) -> tuple[int, dict[str, Any]]:
    client = OPNsenseClient(host)
    try:
        out = client.get("/api/firewall/source_nat/searchRule")
        rows = out.get("rows", []) if isinstance(out, dict) else []
        return 200, {"ok": True, "data": {"rules": rows, "total": len(rows)}}
    except OPNsenseAuthError as e:
        return 401, {"ok": False, "error": "auth", "detail": str(e)}
    except OPNsenseTimeoutError as e:
        return 504, {"ok": False, "error": "timeout", "detail": str(e)}
    except OPNsenseError as e:
        log.exception("nat list failed")
        return 502, {"ok": False, "error": "upstream", "detail": str(e)}


def build_nat_action_payload(
    host: OPNsenseHost,
    plugin_dir: str,
    body: dict[str, Any],
    actor: str = "plugin",
    read_only: bool = False,
) -> tuple[int, dict[str, Any]]:
    if read_only:
        return 403, {"ok": False, "error": "read_only", "detail": "plugin config has read_only=true"}
    action = str(body.get("action", "")).lower()
    if action not in ("create", "delete"):
        return 400, {"ok": False, "error": "bad_request", "detail": "action must be create|delete"}

    client = OPNsenseClient(host)
    audit = AuditLog(_audit_log_path(plugin_dir))
    writer = NatWriter(client, audit, actor=actor)

    try:
        if action == "create":
            rule = body.get("rule") or {}
            try:
                payload = NatInput(
                    interface=str(rule.get("interface", "")),
                    target=str(rule.get("target", "")),
                    source_net=str(rule.get("source_net", "any")) or "any",
                    destination_net=str(rule.get("destination_net", "any")) or "any",
                    description=str(rule.get("description", "")),
                    enabled=bool(rule.get("enabled", True)),
                    ipprotocol=str(rule.get("ipprotocol", "inet")),
                    protocol=str(rule.get("protocol", "any")),
                )
            except (TypeError, ValueError) as e:
                return 400, {"ok": False, "error": "bad_request", "detail": str(e)}
            try:
                result = writer.create(payload)
            except ValueError as e:
                return 400, {"ok": False, "error": "validation", "detail": str(e)}
        else:  # delete
            uuid = str(body.get("uuid", ""))
            if not uuid:
                return 400, {"ok": False, "error": "bad_request", "detail": "uuid is required"}
            result = writer.delete(uuid)
    except OPNsenseAuthError as e:
        return 401, {"ok": False, "error": "auth", "detail": str(e)}
    except OPNsenseTimeoutError as e:
        return 504, {"ok": False, "error": "timeout", "detail": str(e)}
    except OPNsenseError as e:
        log.exception("nat action %s failed", action)
        return 502, {"ok": False, "error": "upstream", "detail": str(e)}

    if not result.ok:
        return 502, {"ok": False, "error": "upstream", "detail": result.detail or "write failed"}
    return 200, {"ok": True, "data": {"uuid": result.uuid, "action": action}}
