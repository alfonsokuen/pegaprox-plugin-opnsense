"""Unbound host-override route.

Mounted on `/api/plugins/opnsense/api/unbound`.

  GET  → list host overrides
  POST {action: "create", host: {...}}  → addHostOverride + reconfigure
  POST {action: "delete", uuid: "..."}  → delHostOverride + reconfigure

Refuses writes when plugin config has read_only=true.
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
from src.writers import AuditLog, UnboundHostInput, UnboundWriter

log = logging.getLogger(__name__)


def _audit_log_path(plugin_dir: str) -> str:
    state = os.path.join(plugin_dir, "state")
    os.makedirs(state, exist_ok=True)
    return os.path.join(state, "audit.jsonl")


def build_unbound_list_payload(host: OPNsenseHost) -> tuple[int, dict[str, Any]]:
    client = OPNsenseClient(host)
    try:
        out = client.get("/api/unbound/settings/searchHostOverride")
        rows = out.get("rows", []) if isinstance(out, dict) else []
        return 200, {"ok": True, "data": {"hosts": rows, "total": len(rows)}}
    except OPNsenseAuthError as e:
        return 401, {"ok": False, "error": "auth", "detail": str(e)}
    except OPNsenseTimeoutError as e:
        return 504, {"ok": False, "error": "timeout", "detail": str(e)}
    except OPNsenseError as e:
        log.exception("unbound list failed")
        return 502, {"ok": False, "error": "upstream", "detail": str(e)}


def build_unbound_action_payload(
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
    writer = UnboundWriter(client, audit, actor=actor)

    try:
        if action == "create":
            h = body.get("host") or {}
            try:
                payload = UnboundHostInput(
                    hostname=str(h.get("hostname", "")),
                    domain=str(h.get("domain", "")),
                    server=str(h.get("server", "")),
                    rr=str(h.get("rr", "A")),
                    description=str(h.get("description", "")),
                    enabled=bool(h.get("enabled", True)),
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
        log.exception("unbound action %s failed", action)
        return 502, {"ok": False, "error": "upstream", "detail": str(e)}

    if not result.ok:
        return 502, {"ok": False, "error": "upstream", "detail": result.detail or "write failed"}
    return 200, {"ok": True, "data": {"uuid": result.uuid, "action": action}}
