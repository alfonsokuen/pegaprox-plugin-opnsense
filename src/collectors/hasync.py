"""HA sync configuration snapshot.

Reads `/api/core/hasync/get` and surfaces the operationally-relevant flags.
The endpoint returns option-style fields where one nested dict has
`selected: 1` per group; we collapse those to plain values.
"""
from __future__ import annotations

from typing import Any, TypedDict

from src.client import OPNsenseClient


class HASyncSnapshot(TypedDict):
    enabled: bool
    pfsync_interface: str
    pfsync_peer_ip: str
    pfsync_version: str
    sync_to_ip: str
    sync_compatibility: str
    sync_disable_preempt: bool
    sync_disconnect_ppps: bool


def _selected_value(option_dict: Any) -> str:
    """OPNsense option groups: {key: {value, selected}}. Return the selected `value`."""
    if not isinstance(option_dict, dict):
        return ""
    for entry in option_dict.values():
        if isinstance(entry, dict) and entry.get("selected"):
            return str(entry.get("value", ""))
    return ""


def _bool01(value: Any) -> bool:
    try:
        return int(str(value).strip()) == 1
    except (ValueError, AttributeError):
        return False


def collect_hasync(client: OPNsenseClient) -> HASyncSnapshot:
    payload = client.get("/api/core/hasync/get")
    h = payload.get("hasync", {}) if isinstance(payload, dict) else {}

    pfsync_iface = _selected_value(h.get("pfsyncinterface"))
    enabled = bool(pfsync_iface) and pfsync_iface.lower() != "disabled"

    return HASyncSnapshot(
        enabled=enabled,
        pfsync_interface=pfsync_iface,
        pfsync_peer_ip=str(h.get("pfsyncpeerip", "")),
        pfsync_version=_selected_value(h.get("pfsyncversion")),
        sync_to_ip=str(h.get("synchronizetoip", "")),
        sync_compatibility=_selected_value(h.get("synchronizecompatibility")),
        sync_disable_preempt=_bool01(h.get("disablepreempt")),
        sync_disconnect_ppps=_bool01(h.get("disconnectppps")),
    )
