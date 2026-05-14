"""1:1 NAT (BINAT) CRUD writer.

Endpoints (`/api/firewall/one_to_one/*`) follow the same shape as outbound
NAT but apply at `apply` instead of `reconfigure`. Verified live against
OPNsense 26.1.2 (2026-05-10): `searchRule` + `getRule` round-trip OK.

Port-forwarding (rdr) is not exposed via the OPNsense REST API on this
release — no `/api/firewall/{forward,portfwd,nat}/*` endpoints respond.
Tracking that in the changelog as out-of-scope until upstream ships it.
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
class OneToOneNatInput:
    interface: str          # e.g. "wan", "lan"
    external: str           # external (public) IP/alias being mapped
    source_net: str         # internal IP/alias on the inside
    destination_net: str = "any"
    description: str = ""
    enabled: bool = True
    type: str = "binat"     # binat (bidirectional) | nat (inbound only)
    log: bool = False
    sequence: str = "100"

    def to_payload(self) -> dict[str, Any]:
        return {
            "rule": {
                "enabled": "1" if self.enabled else "0",
                "log": "1" if self.log else "0",
                "sequence": self.sequence,
                "interface": self.interface,
                "type": self.type,
                "source_net": self.source_net,
                "source_not": "0",
                "destination_net": self.destination_net,
                "destination_not": "0",
                "external": self.external,
                "description": self.description,
            }
        }


OneToOneResult = AliasResult
one_to_one_result_to_dict = alias_result_to_dict


class OneToOneNatWriter:
    BASE = "/api/firewall/one_to_one"

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
        out = self.client.get(f"{self.BASE}/searchRule", **params)
        return out.get("rows", []) if isinstance(out, dict) else []

    def get(self, uuid: str) -> dict[str, Any]:
        return self.client.get(f"{self.BASE}/getRule/{uuid}")

    def create(self, payload: OneToOneNatInput) -> OneToOneResult:
        self._validate(payload)
        with TimedAction() as t:
            try:
                resp = self.client.post(f"{self.BASE}/addRule", payload.to_payload())
            except OPNsenseError as e:
                self._record("one_to_one.create", payload.description or payload.interface, "error", t, str(e))
                return OneToOneResult(ok=False, detail=str(e))
            uuid = str(resp.get("uuid", ""))
            if not uuid:
                self._record("one_to_one.create", payload.interface, "error", t, "no uuid in response")
                return OneToOneResult(ok=False, detail="OPNsense did not return uuid")
            try:
                self._apply()
            except OPNsenseError as e:
                try:
                    self.client.post(f"{self.BASE}/delRule/{uuid}", {})
                except OPNsenseError:
                    pass
                self._record("one_to_one.create", payload.interface, "error", t, f"apply failed → rolled back: {e}")
                return OneToOneResult(ok=False, detail=f"apply failed → rolled back: {e}")
        sync = self._maybe_sync()
        entry = self._record("one_to_one.create", uuid, "ok", t, payload.description, payload_sha256=hash_payload(payload.to_payload()))
        return OneToOneResult(ok=True, uuid=uuid, sync=sync, audit=entry)

    def delete(self, uuid: str) -> OneToOneResult:
        with TimedAction() as t:
            try:
                self.client.post(f"{self.BASE}/delRule/{uuid}", {})
                self._apply()
            except OPNsenseError as e:
                self._record("one_to_one.delete", uuid, "error", t, str(e))
                return OneToOneResult(ok=False, uuid=uuid, detail=str(e))
        sync = self._maybe_sync()
        entry = self._record("one_to_one.delete", uuid, "ok", t)
        return OneToOneResult(ok=True, uuid=uuid, sync=sync, audit=entry)

    def _validate(self, payload: OneToOneNatInput) -> None:
        if not payload.interface:
            raise ValueError("interface is required")
        if not payload.external:
            raise ValueError("external IP/alias is required")
        if not payload.source_net:
            raise ValueError("source_net (internal IP/alias) is required")
        if payload.type not in ("binat", "nat"):
            raise ValueError(f"type must be binat|nat, got {payload.type!r}")

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
