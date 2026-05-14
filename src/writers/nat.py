"""Outbound (source) NAT CRUD writer.

Endpoints (`/api/firewall/source_nat/*`) follow the same shape as filter
rules: addRule / setRule / delRule / get / searchRule, with `apply` to
commit. Verified against OPNsense 26.1.2 in the lab.

Scope of v1.4.0: outbound source NAT only. 1:1 NAT (`/api/firewall/one_to_one/*`)
and port-forward (rdr) ship in a follow-up.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from src.client import OPNsenseClient, OPNsenseError

from .alias import AliasResult, alias_result_to_dict
from .audit import AuditEntry, AuditLog, TimedAction, hash_payload
from .hasync_writer import HAVerifier, SyncResult

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class NatInput:
    interface: str          # e.g. "wan", "lan"
    target: str             # IP or alias for outbound translation
    source_net: str = "any"
    destination_net: str = "any"
    description: str = ""
    enabled: bool = True
    ipprotocol: str = "inet"  # inet | inet6
    protocol: str = "any"     # any | tcp | udp | tcp/udp | icmp

    def to_payload(self) -> dict[str, Any]:
        return {
            "rule": {
                "disabled": "0" if self.enabled else "1",
                "interface": self.interface,
                "ipprotocol": self.ipprotocol,
                "protocol": self.protocol,
                "source_net": self.source_net,
                "destination_net": self.destination_net,
                "target": self.target,
                "description": self.description,
            }
        }


# Re-export alias result type for shape consistency.
NatResult = AliasResult
nat_result_to_dict = alias_result_to_dict


class NatWriter:
    BASE = "/api/firewall/source_nat"

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

    # ----- read --------------------------------------------------------

    def search(self, phrase: str = "") -> list[dict[str, Any]]:
        params = {"searchPhrase": phrase} if phrase else {}
        out = self.client.get(f"{self.BASE}/searchRule", **params)
        return out.get("rows", []) if isinstance(out, dict) else []

    def get(self, uuid: str) -> dict[str, Any]:
        return self.client.get(f"{self.BASE}/getRule/{uuid}")

    # ----- write -------------------------------------------------------

    def create(self, payload: NatInput) -> NatResult:
        self._validate(payload)
        with TimedAction() as t:
            try:
                resp = self.client.post(f"{self.BASE}/addRule", payload.to_payload())
            except OPNsenseError as e:
                self._record("nat.create", payload.description or payload.interface, "error", t, str(e))
                return NatResult(ok=False, detail=str(e))
            uuid = str(resp.get("uuid", ""))
            if not uuid:
                self._record("nat.create", payload.interface, "error", t, "no uuid in response")
                return NatResult(ok=False, detail="OPNsense did not return uuid")
            try:
                self._apply()
            except OPNsenseError as e:
                try:
                    self.client.post(f"{self.BASE}/delRule/{uuid}", {})
                except OPNsenseError:
                    pass
                self._record("nat.create", payload.interface, "error", t, f"apply failed → rolled back: {e}")
                return NatResult(ok=False, detail=f"apply failed → rolled back: {e}")
        sync = self._maybe_sync()
        entry = self._record("nat.create", uuid, "ok", t, payload.description, payload_sha256=hash_payload(payload.to_payload()))
        return NatResult(ok=True, uuid=uuid, sync=sync, audit=entry)

    def update(self, uuid: str, payload: NatInput) -> NatResult:
        self._validate(payload)
        with TimedAction() as t:
            try:
                self.client.post(f"{self.BASE}/setRule/{uuid}", payload.to_payload())
                self._apply()
            except OPNsenseError as e:
                self._record("nat.update", uuid, "error", t, str(e))
                return NatResult(ok=False, uuid=uuid, detail=str(e))
        sync = self._maybe_sync()
        entry = self._record("nat.update", uuid, "ok", t, payload_sha256=hash_payload(payload.to_payload()))
        return NatResult(ok=True, uuid=uuid, sync=sync, audit=entry)

    def delete(self, uuid: str) -> NatResult:
        with TimedAction() as t:
            try:
                self.client.post(f"{self.BASE}/delRule/{uuid}", {})
                self._apply()
            except OPNsenseError as e:
                self._record("nat.delete", uuid, "error", t, str(e))
                return NatResult(ok=False, uuid=uuid, detail=str(e))
        sync = self._maybe_sync()
        entry = self._record("nat.delete", uuid, "ok", t)
        return NatResult(ok=True, uuid=uuid, sync=sync, audit=entry)

    # ----- internals ---------------------------------------------------

    def _validate(self, payload: NatInput) -> None:
        if not payload.interface:
            raise ValueError("interface is required")
        if not payload.target:
            raise ValueError("target is required (IP or alias)")
        if payload.ipprotocol not in ("inet", "inet6"):
            raise ValueError(f"ipprotocol must be inet|inet6, got {payload.ipprotocol!r}")

    def _apply(self) -> None:
        self.client.post(f"{self.BASE}/apply", {})

    def _maybe_sync(self) -> SyncResult | None:
        if self.ha is None:
            return None
        return self.ha.verify_robust(f"{self.BASE}/searchRule")

    def _record(
        self, action: str, target: str, result: str,
        timer: TimedAction, detail: str = "", payload_sha256: str = "",
    ) -> AuditEntry:
        entry = AuditEntry.now(
            user=self.actor,
            action=action,
            target=target,
            host=self.host_name,
            result=result,
            duration_ms=timer.elapsed_ms,
            detail=detail,
        payload_sha256=payload_sha256,
        )
        try:
            self.audit.append(entry)
        except OSError as e:
            log.warning("audit log write failed: %s", e)
        return entry
