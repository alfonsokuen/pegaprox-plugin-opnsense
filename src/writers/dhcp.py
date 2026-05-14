"""DHCPv4 (Kea) reservation CRUD writer.

OPNsense 26.x uses Kea as the DHCP backend. Endpoints:
  /api/kea/dhcpv4/{addReservation,delReservation,searchReservation,getReservation}
  /api/kea/service/reconfigure   — apply

A reservation pins a MAC address to a specific IP within a Kea subnet. The
subnet itself is referenced by its OPNsense UUID, not its CIDR — the UUID
must already exist in the Kea config; this writer does not manage subnets.

Lab note: at the time of writing the lab has no Kea subnet configured;
v1.10.0 ships the reservation surface only. Subnet management would be a
separate writer when a use-case appears.
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

_MAC_RE = re.compile(r"^[0-9a-fA-F]{2}([:-][0-9a-fA-F]{2}){5}$")
_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


@dataclass(frozen=True)
class DhcpReservationInput:
    subnet: str             # OPNsense subnet UUID
    ip_address: str         # IPv4 within the subnet
    hw_address: str         # MAC, AA:BB:CC:DD:EE:FF or aa-bb-...
    hostname: str           # client hostname
    description: str = ""

    def to_payload(self) -> dict[str, Any]:
        return {
            "reservation": {
                "subnet": self.subnet,
                "ip_address": self.ip_address,
                "hw_address": self.hw_address,
                "hostname": self.hostname,
                "description": self.description,
            }
        }


DhcpResult = AliasResult
dhcp_result_to_dict = alias_result_to_dict


class DhcpReservationWriter:
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
        out = self.client.get(f"{self.BASE}/searchReservation", **params)
        return out.get("rows", []) if isinstance(out, dict) else []

    def get(self, uuid: str) -> dict[str, Any]:
        return self.client.get(f"{self.BASE}/getReservation/{uuid}")

    def create(self, payload: DhcpReservationInput) -> DhcpResult:
        self._validate(payload)
        with TimedAction() as t:
            try:
                resp = self.client.post(f"{self.BASE}/addReservation", payload.to_payload())
            except OPNsenseError as e:
                self._record("dhcp_reservation.create", payload.hostname or "?", "error", t, str(e))
                return DhcpResult(ok=False, detail=str(e))
            uuid = str(resp.get("uuid", ""))
            if not uuid:
                self._record("dhcp_reservation.create", payload.hostname, "error", t, "no uuid in response")
                return DhcpResult(ok=False, detail="OPNsense did not return uuid")
            try:
                self._apply()
            except OPNsenseError as e:
                try:
                    self.client.post(f"{self.BASE}/delReservation/{uuid}", {})
                except OPNsenseError:
                    pass
                self._record("dhcp_reservation.create", payload.hostname, "error", t, f"apply failed → rolled back: {e}")
                return DhcpResult(ok=False, detail=f"apply failed → rolled back: {e}")
        sync = self._maybe_sync()
        entry = self._record(
            "dhcp_reservation.create", uuid, "ok", t, payload.description,
            payload_sha256=hash_payload(payload.to_payload()),
        )
        return DhcpResult(ok=True, uuid=uuid, sync=sync, audit=entry)

    def delete(self, uuid: str) -> DhcpResult:
        with TimedAction() as t:
            try:
                self.client.post(f"{self.BASE}/delReservation/{uuid}", {})
                self._apply()
            except OPNsenseError as e:
                self._record("dhcp_reservation.delete", uuid, "error", t, str(e))
                return DhcpResult(ok=False, uuid=uuid, detail=str(e))
        sync = self._maybe_sync()
        entry = self._record("dhcp_reservation.delete", uuid, "ok", t)
        return DhcpResult(ok=True, uuid=uuid, sync=sync, audit=entry)

    def _validate(self, payload: DhcpReservationInput) -> None:
        if not payload.subnet:
            raise ValueError("subnet UUID is required")
        if not _IPV4_RE.match(payload.ip_address or ""):
            raise ValueError(f"ip_address must be IPv4, got {payload.ip_address!r}")
        if not _MAC_RE.match(payload.hw_address or ""):
            raise ValueError(f"hw_address must be MAC (XX:XX:XX:XX:XX:XX), got {payload.hw_address!r}")
        if not payload.hostname:
            raise ValueError("hostname is required")

    def _apply(self) -> None:
        self.client.post(self.APPLY, {})

    def _maybe_sync(self) -> SyncResult | None:
        if self.ha is None:
            return None
        return self.ha.verify_robust(f"{self.BASE}/searchReservation")

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
