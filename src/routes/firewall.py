"""DNAT, filter rules and aliases: strict input and verified write outcomes."""
from __future__ import annotations

import os
import re
from typing import Any

from src.client import (
    OPNsenseAuthError,
    OPNsenseClient,
    OPNsenseError,
    OPNsenseTimeoutError,
)
from src.writers.alias import AliasInput
from src.writers.audit import AuditLog, hash_payload
from src.writers.port_forward import PortForwardInput
from src.writers.rule import RuleInput
from src.writers.verified import (
    DEFAULT_HA_VERIFY_ATTEMPTS,
    DEFAULT_HA_VERIFY_BACKOFF,
    SPECS,
    VerifiedFirewallWriter,
    selected,
    validate_revision,
    validate_uuid,
)


def _bool(data, key, default):
    value = data.get(key, default)
    if not isinstance(value, bool):
        raise TypeError(f"{key} must be a JSON boolean")
    return value


def _str(data, key, default="", required=False):
    value = data.get(key, default)
    if not isinstance(value, str) or len(value) > (65536 if key == "content" else 2048):
        raise ValueError(f"{key} must be a string within the supported length")
    if "\x00" in value or (required and not value.strip()):
        raise ValueError(f"{key} is required or invalid")
    return value.strip()


def _enum(value, name, choices):
    if value not in choices:
        raise ValueError(f"{name} must be one of {', '.join(choices)}")
    return value


def _port(data, key, default="", required=False, allow_range=True):
    value = _str(data, key, default, required)
    if value.lower() == "any":
        value = ""
    if required and not value:
        raise ValueError(f"{key} is required")
    if not value:
        return value
    if re.fullmatch(r"\d+(?:[:-]\d+)?", value):
        ports = [int(v) for v in re.split(r"[:-]", value)]
        if any(v < 1 or v > 65535 for v in ports) or (len(ports) > 1 and (not allow_range or ports[0] > ports[1])):
            raise ValueError(f"{key} must be a valid port or ascending range")
    elif not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*", value):
        raise ValueError(f"{key} must be a port, alias or range")
    return value


def parse_payload(resource: str, data: Any) -> dict:
    if not isinstance(data, dict):
        raise TypeError("rule/alias must be a JSON object")
    if resource == "aliases":
        name = _str(data, "name", required=True)
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,254}", name):
            raise ValueError("name must be an identifier without spaces")
        alias_type = _enum(_str(data, "type", "host"), "type", ("host", "network", "port", "url", "urltable", "geoip", "external"))
        return AliasInput(name=name, type=alias_type, content=_str(data, "content", required=alias_type != "external"),
            description=_str(data, "description"), enabled=_bool(data, "enabled", True),
            proto=_str(data, "proto")).to_payload()
    sequence = data.get("sequence", 1)
    if isinstance(sequence, str) and sequence.isdigit():
        sequence = int(sequence)
    if isinstance(sequence, bool) or not isinstance(sequence, int) or not 1 <= sequence <= 999999:
        raise ValueError("sequence must be an integer between 1 and 999999")
    common = {"interface": _str(data, "interface", required=True),
        "ipprotocol": _enum(_str(data, "ipprotocol", "inet"), "ipprotocol", ("inet", "inet6", "inet46")),
        "protocol": _enum(_str(data, "protocol", "tcp" if resource == "port_forward" else "any").lower(), "protocol", ("tcp", "udp", "tcp/udp", "any", "icmp", "icmp6", "esp", "gre")),
        "source_net": _str(data, "source_net", "any", True), "source_port": _port(data, "source_port"),
        "destination_net": _str(data, "destination_net", "wanip" if resource == "port_forward" else "any", True),
        "destination_port": _port(data, "destination_port", required=resource == "port_forward"),
        "description": _str(data, "description"), "enabled": _bool(data, "enabled", False), "sequence": sequence}
    if resource == "port_forward":
        _enum(common["protocol"], "protocol", ("tcp", "udp", "tcp/udp"))
        if "target_port" not in data and "local_port" in data:
            data = {**data, "target_port": data["local_port"]}
        return PortForwardInput(**common, target=_str(data, "target", required=True),
            target_port=_port(data, "target_port", required=True, allow_range=False),
            log=_bool(data, "log", False),
            filter_association=_enum(_str(data, "filter_association"), "filter_association", ("", "pass", "rule")),
            natreflection=_enum(_str(data, "natreflection"), "natreflection", ("", "purenat", "disable"))).to_payload()
    payload = RuleInput(**common, action=_enum(_str(data, "action", "pass"), "action", ("pass", "block", "reject")),
        direction=_enum(_str(data, "direction", "in"), "direction", ("in", "out", "any"))).to_payload()
    payload["rule"].update(log="1" if _bool(data, "log", False) else "0", quick="1" if _bool(data, "quick", True) else "0")
    if payload["rule"]["protocol"] == "tcp/udp":
        payload["rule"]["protocol"] = "TCP/UDP"
    return payload


def normalize(resource: str, row: dict) -> dict:
    row = selected(row)
    # API getItem includes URL alias credentials. Never return raw objects.
    fields = ("uuid", "name", "type", "content", "description", "proto") if resource == "aliases" else (
        "uuid", "interface", "ipprotocol", "protocol", "sequence", "source_net", "source_port",
        "destination_net", "destination_port", "description", "action", "direction", "target", "natreflection")
    result = {key: row[key] for key in fields if key in row}
    if resource == "port_forward":
        for group in ("source", "destination"):
            nested = row.get(group, {})
            for suffix, key in (("network", "net"), ("port", "port")):
                result[f"{group}_{key}"] = row.get(f"{group}.{suffix}", nested.get(suffix, "") if isinstance(nested, dict) else "")
        result.update(target_port=row.get("local-port", ""), description=row.get("descr", ""),
            enabled=str(row.get("disabled", "0")) != "1", filter_association=row.get("pass", ""))
    else:
        result["enabled"] = str(row.get("enabled", "1")) == "1"
    if resource != "aliases":
        result["log"] = str(row.get("log", "0")) == "1"
        result["protocol"] = str(row.get("protocol", "any")).lower()
        result["quick"] = str(row.get("quick", "1")) == "1"
    elif isinstance(result.get("content"), str):
        result["content"] = result["content"].replace(",", "\n")
    return result


def _error(exc):
    code, error = (401, "auth") if isinstance(exc, OPNsenseAuthError) else (504, "timeout") if isinstance(exc, OPNsenseTimeoutError) else (502, "upstream")
    result = {"ok": False, "error": error, "detail": str(exc)}
    if "HTTP 404" in str(exc):
        result["supported"] = False
    return code, result


def build_firewall_list_payload(host, resource="port_forward") -> tuple[int, dict[str, Any]]:
    if resource not in SPECS:
        return 400, {"ok": False, "error": "bad_request", "detail": "Unknown resource"}
    try:
        writer = VerifiedFirewallWriter(OPNsenseClient(host), None, resource)
        rows = []
        for row in writer.search():
            try:
                uuid = validate_uuid(row.get("uuid"))
            except (ValueError, TypeError):
                rows.append({**normalize(resource, row), "editable": False})
                continue
            # Search grids contain display values and can omit form fields.
            # Always obtain the actual editable values before offering editing.
            detail = writer.get(uuid)
            rows.append({**normalize(resource, detail), "uuid": uuid, "editable": True, "revision": hash_payload(detail)})
        key = "aliases" if resource == "aliases" else "rules"
        return 200, {"ok": True, "data": {key: rows, "total": len(rows), "supported": True,
            "capabilities": {"create": True, "update": True, "delete": True}}}
    except (OPNsenseError, ValueError) as exc:
        return _error(exc)


def build_firewall_action_payload(host, plugin_dir, body, actor="plugin", read_only=False,
                                  peer_host=None, resource="port_forward",
                                  ha_verify_attempts=DEFAULT_HA_VERIFY_ATTEMPTS,
                                  ha_verify_backoff=DEFAULT_HA_VERIFY_BACKOFF,
                                  ha_sync_mode="automatic") -> tuple[int, dict[str, Any]]:
    if read_only:
        return 403, {"ok": False, "error": "read_only", "detail": "Plugin is read-only"}
    try:
        if resource not in SPECS or not isinstance(body, dict):
            raise ValueError("Expected a JSON object and valid resource")
        action = body.get("action")
        if action not in ("create", "update", "delete"):
            raise ValueError("action must be create|update|delete")
        uuid = validate_uuid(body.get("uuid")) if action != "create" else ""
        revision = validate_revision(body.get("revision")) if action != "create" else ""
        payload = parse_payload(resource, body.get("alias" if resource == "aliases" else "rule")) if action != "delete" else None
        audit = AuditLog(os.path.join(plugin_dir, "state", "audit.jsonl"))
        writer = VerifiedFirewallWriter(OPNsenseClient(host), audit, resource, actor,
            peer=OPNsenseClient(peer_host) if peer_host else None,
            ha_verify_attempts=ha_verify_attempts, ha_verify_backoff=ha_verify_backoff,
            ha_sync_mode=ha_sync_mode)
        result = writer.execute(action, payload, uuid, revision)
        status = 200 if result["ok"] else {"validation": 422, "auth": 401, "timeout": 504, "ha_unverified": 409, "ha_unsafe": 409, "conflict": 409}.get(result.get("error"), 502)
        envelope = {"ok": result["ok"], "data": result}
        if not result["ok"]:
            envelope.update(error=result.get("error", "upstream"), detail=result["detail"])
        return status, envelope
    except (ValueError, TypeError) as exc:
        return 400, {"ok": False, "error": "bad_request", "detail": str(exc)}
    except (OPNsenseError, OSError) as exc:
        return _error(exc)


def build_port_forward_list_payload(host):
    return build_firewall_list_payload(host, "port_forward")


def build_rules_list_payload(host):
    return build_firewall_list_payload(host, "rules")


def build_aliases_list_payload(host):
    return build_firewall_list_payload(host, "aliases")


def build_port_forward_action_payload(host, plugin_dir, body, **kwargs):
    return build_firewall_action_payload(host, plugin_dir, body, resource="port_forward", **kwargs)


def build_rules_action_payload(host, plugin_dir, body, **kwargs):
    return build_firewall_action_payload(host, plugin_dir, body, resource="rules", **kwargs)


def build_aliases_action_payload(host, plugin_dir, body, **kwargs):
    return build_firewall_action_payload(host, plugin_dir, body, resource="aliases", **kwargs)
