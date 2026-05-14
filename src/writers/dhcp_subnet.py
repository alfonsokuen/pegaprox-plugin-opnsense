"""Kea DHCPv4 subnet CRUD writer.

Endpoints (`/api/kea/dhcpv4/{addSubnet,delSubnet,searchSubnet,getSubnet}`)
follow the Kea config-tree convention: payload root key is `subnet4`,
required field is `subnet` (CIDR like `192.168.1.0/24`). Verified live
against OPNsense 26.1.2 (2026-05-11): addSubnet → uuid → delSubnet
round-trip OK with minimal `{subnet, description}` payload.

Scope: subnet definition (CIDR, pools, next_server, match_client_id,
description). The dozen `option_data.*` fields exposed by `getSubnet`
(DNS servers, routers, static routes, etc.) are intentionally out-of-
scope for v1.12.0; a single Pythonic input dataclass would balloon. If
operators need DHCP options they can edit them through the OPNsense
GUI; the plugin will surface them in the table.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any

from src.client import OPNsenseClient, OPNsenseError

from .alias import AliasResult, alias_result_to_dict
from .audit import AuditEntry, AuditLog, TimedAction, hash_payload
from .hasync_writer import HAVerifier, SyncResult

log = logging.getLogger(__name__)

_CIDR_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}$")


@dataclass(frozen=True)
class DhcpSubnetInput:
    subnet: str             # CIDR e.g. "192.168.1.0/24"
    description: str = ""
    pools: str = ""         # e.g. "192.168.1.100-192.168.1.200"
    next_server: str = ""
    match_client_id: bool = True

    def to_payload(self) -> dict[str, Any]:
        return {
            "subnet4": {
                "subnet": self.subnet,
                "description": self.description,
                "pools": self.pools,
                "next_server": self.next_server,
                "match-client-id": "1" if self.match_client_id else "0",
            }
        }


DhcpSubnetResult = AliasResult
dhcp_subnet_result_to_dict = alias_result_to_dict


class DhcpSubnetWriter:
    BASE = "/api/kea/dhcpv4"
    APPLY = "/api/kea/service/reconfigure"

    def __init__(
        self,
        client: OPNsenseClient,
        audit: AuditLog,
        ha: HAVerifier | None = None,
        actor: str = "plugin",
        host_name: str = "",
    ) -> None:
        self.client = client
        self.audit = audit
        self.ha = ha
        self.actor = actor
        self.host_name = host_name or client.host.name

    def search(self, phrase: str = "") -> list[dict[str, Any]]:
        params = {"searchPhrase": phrase} if phrase else {}
        out = self.client.get(f"{self.BASE}/searchSubnet", **params)
        return out.get("rows", []) if isinstance(out, dict) else []

    def get(self, uuid: str) -> dict[str, Any]:
        return self.client.get(f"{self.BASE}/getSubnet/{uuid}")

    def create(self, payload: DhcpSubnetInput) -> DhcpSubnetResult:
        self._validate(payload)
        with TimedAction() as t:
            try:
                resp = self.client.post(f"{self.BASE}/addSubnet", payload.to_payload())
            except OPNsenseError as e:
                self._record("dhcp_subnet.create", payload.subnet or "?", "error", t, str(e))
                return DhcpSubnetResult(ok=False, detail=str(e))
            uuid = str(resp.get("uuid", ""))
            if not uuid:
                self._record("dhcp_subnet.create", payload.subnet, "error", t, "no uuid in response")
                return DhcpSubnetResult(ok=False, detail="OPNsense did not return uuid")
            try:
                self._apply()
            except OPNsenseError as e:
                try:
                    self.client.post(f"{self.BASE}/delSubnet/{uuid}", {})
                except OPNsenseError:
                    pass
                self._record("dhcp_subnet.create", payload.subnet, "error", t, f"apply failed → rolled back: {e}")
                return DhcpSubnetResult(ok=False, detail=f"apply failed → rolled back: {e}")
        sync = self._maybe_sync()
        entry = self._record(
            "dhcp_subnet.create", uuid, "ok", t, payload.description,
            payload_sha256=hash_payload(payload.to_payload()),
        )
        return DhcpSubnetResult(ok=True, uuid=uuid, sync=sync, audit=entry)

    def delete(self, uuid: str) -> DhcpSubnetResult:
        with TimedAction() as t:
            try:
                self.client.post(f"{self.BASE}/delSubnet/{uuid}", {})
                self._apply()
            except OPNsenseError as e:
                self._record("dhcp_subnet.delete", uuid, "error", t, str(e))
                return DhcpSubnetResult(ok=False, uuid=uuid, detail=str(e))
        sync = self._maybe_sync()
        entry = self._record("dhcp_subnet.delete", uuid, "ok", t)
        return DhcpSubnetResult(ok=True, uuid=uuid, sync=sync, audit=entry)

    def _validate(self, payload: DhcpSubnetInput) -> None:
        if not _CIDR_RE.match(payload.subnet or ""):
            raise ValueError(f"subnet must be IPv4 CIDR (e.g. 192.168.1.0/24), got {payload.subnet!r}")

    def _apply(self) -> None:
        self.client.post(self.APPLY, {})

    def _maybe_sync(self) -> SyncResult | None:
        if self.ha is None:
            return None
        return self.ha.verify_robust(f"{self.BASE}/searchSubnet")

    def _record(
        self, action: str, target: str, result: str,
        timer: TimedAction, detail: str = "", payload_sha256: str = "",
    ) -> AuditEntry:
        entry = AuditEntry.now(
            user=self.actor, action=action, target=target,
            host=self.host_name, result=result,
            duration_ms=timer.elapsed_ms, detail=detail,
            payload_sha256=payload_sha256,
        )
        try:
            self.audit.append(entry)
        except OSError as e:
            log.warning("audit log write failed: %s", e)
        return entry
