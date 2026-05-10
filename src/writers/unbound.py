"""Unbound DNS host- and domain-override CRUD.

Endpoints (`/api/unbound/settings/*`) follow the same shape as filter rules:
addHostOverride / delHostOverride / searchHostOverride and
addDomainOverride / delDomainOverride / searchDomainOverride, with
`service/reconfigure` to commit. Verified live against OPNsense 26.1.2.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from src.client import OPNsenseClient, OPNsenseError

from .alias import AliasResult, alias_result_to_dict
from .audit import AuditEntry, AuditLog, TimedAction
from .hasync_writer import HAVerifier, SyncResult

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class UnboundHostInput:
    hostname: str           # e.g. "router"
    domain: str             # e.g. "lab.local"
    server: str             # IPv4 or IPv6 to resolve to
    rr: str = "A"           # A | AAAA | MX
    description: str = ""
    enabled: bool = True

    def to_payload(self) -> dict[str, Any]:
        return {
            "host": {
                "enabled": "1" if self.enabled else "0",
                "hostname": self.hostname,
                "domain": self.domain,
                "rr": self.rr,
                "server": self.server,
                "description": self.description,
            }
        }


UnboundResult = AliasResult
unbound_result_to_dict = alias_result_to_dict


class UnboundWriter:
    BASE = "/api/unbound/settings"
    APPLY = "/api/unbound/service/reconfigure"

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
        out = self.client.get(f"{self.BASE}/searchHostOverride", **params)
        return out.get("rows", []) if isinstance(out, dict) else []

    def get(self, uuid: str) -> dict[str, Any]:
        return self.client.get(f"{self.BASE}/getHostOverride/{uuid}")

    def create(self, payload: UnboundHostInput) -> UnboundResult:
        self._validate(payload)
        with TimedAction() as t:
            try:
                resp = self.client.post(f"{self.BASE}/addHostOverride", payload.to_payload())
            except OPNsenseError as e:
                self._record("unbound.create", payload.hostname or "?", "error", t, str(e))
                return UnboundResult(ok=False, detail=str(e))
            uuid = str(resp.get("uuid", ""))
            if not uuid:
                self._record("unbound.create", payload.hostname, "error", t, "no uuid in response")
                return UnboundResult(ok=False, detail="OPNsense did not return uuid")
            try:
                self._apply()
            except OPNsenseError as e:
                try:
                    self.client.post(f"{self.BASE}/delHostOverride/{uuid}", {})
                except OPNsenseError:
                    pass
                self._record("unbound.create", payload.hostname, "error", t, f"apply failed → rolled back: {e}")
                return UnboundResult(ok=False, detail=f"apply failed → rolled back: {e}")
        sync = self._maybe_sync()
        entry = self._record("unbound.create", uuid, "ok", t, payload.description)
        return UnboundResult(ok=True, uuid=uuid, sync=sync, audit=entry)

    def delete(self, uuid: str) -> UnboundResult:
        with TimedAction() as t:
            try:
                self.client.post(f"{self.BASE}/delHostOverride/{uuid}", {})
                self._apply()
            except OPNsenseError as e:
                self._record("unbound.delete", uuid, "error", t, str(e))
                return UnboundResult(ok=False, uuid=uuid, detail=str(e))
        sync = self._maybe_sync()
        entry = self._record("unbound.delete", uuid, "ok", t)
        return UnboundResult(ok=True, uuid=uuid, sync=sync, audit=entry)

    def _validate(self, payload: UnboundHostInput) -> None:
        if not payload.hostname:
            raise ValueError("hostname is required")
        if not payload.domain:
            raise ValueError("domain is required")
        if not payload.server:
            raise ValueError("server (IP) is required")
        if payload.rr not in ("A", "AAAA", "MX"):
            raise ValueError(f"rr must be A|AAAA|MX, got {payload.rr!r}")

    def _apply(self) -> None:
        self.client.post(self.APPLY, {})

    def _maybe_sync(self) -> SyncResult | None:
        if self.ha is None:
            return None
        return self.ha.verify(f"{self.BASE}/searchHostOverride")

    def _record(
        self, action: str, target: str, result: str,
        timer: TimedAction, detail: str = "",
    ) -> AuditEntry:
        entry = AuditEntry.now(
            user=self.actor, action=action, target=target,
            host=self.host_name, result=result,
            duration_ms=timer.elapsed_ms, detail=detail,
        )
        try:
            self.audit.append(entry)
        except OSError as e:
            log.warning("audit log write failed: %s", e)
        return entry


# ---------------------------------------------------------------------------
# Domain overrides (forward an entire DNS zone to a different resolver).
# Same lifecycle as host overrides, smaller payload.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class UnboundDomainInput:
    domain: str             # e.g. "internal.lab.local"
    server: str             # IPv4/IPv6 of the resolver to forward to
    description: str = ""
    enabled: bool = True

    def to_payload(self) -> dict[str, Any]:
        return {
            "domain": {
                "enabled": "1" if self.enabled else "0",
                "domain": self.domain,
                "server": self.server,
                "description": self.description,
            }
        }


class UnboundDomainWriter:
    BASE = "/api/unbound/settings"
    APPLY = "/api/unbound/service/reconfigure"

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
        out = self.client.get(f"{self.BASE}/searchDomainOverride", **params)
        return out.get("rows", []) if isinstance(out, dict) else []

    def get(self, uuid: str) -> dict[str, Any]:
        return self.client.get(f"{self.BASE}/getDomainOverride/{uuid}")

    def create(self, payload: UnboundDomainInput) -> UnboundResult:
        self._validate(payload)
        with TimedAction() as t:
            try:
                resp = self.client.post(f"{self.BASE}/addDomainOverride", payload.to_payload())
            except OPNsenseError as e:
                self._record("unbound_domain.create", payload.domain or "?", "error", t, str(e))
                return UnboundResult(ok=False, detail=str(e))
            uuid = str(resp.get("uuid", ""))
            if not uuid:
                self._record("unbound_domain.create", payload.domain, "error", t, "no uuid in response")
                return UnboundResult(ok=False, detail="OPNsense did not return uuid")
            try:
                self._apply()
            except OPNsenseError as e:
                try:
                    self.client.post(f"{self.BASE}/delDomainOverride/{uuid}", {})
                except OPNsenseError:
                    pass
                self._record("unbound_domain.create", payload.domain, "error", t, f"apply failed → rolled back: {e}")
                return UnboundResult(ok=False, detail=f"apply failed → rolled back: {e}")
        sync = self._maybe_sync()
        entry = self._record("unbound_domain.create", uuid, "ok", t, payload.description)
        return UnboundResult(ok=True, uuid=uuid, sync=sync, audit=entry)

    def delete(self, uuid: str) -> UnboundResult:
        with TimedAction() as t:
            try:
                self.client.post(f"{self.BASE}/delDomainOverride/{uuid}", {})
                self._apply()
            except OPNsenseError as e:
                self._record("unbound_domain.delete", uuid, "error", t, str(e))
                return UnboundResult(ok=False, uuid=uuid, detail=str(e))
        sync = self._maybe_sync()
        entry = self._record("unbound_domain.delete", uuid, "ok", t)
        return UnboundResult(ok=True, uuid=uuid, sync=sync, audit=entry)

    def _validate(self, payload: UnboundDomainInput) -> None:
        if not payload.domain:
            raise ValueError("domain is required")
        if "." not in payload.domain:
            raise ValueError("domain must be a fully-qualified zone (contain a dot)")
        if not payload.server:
            raise ValueError("server (IP) is required")

    def _apply(self) -> None:
        self.client.post(self.APPLY, {})

    def _maybe_sync(self) -> SyncResult | None:
        if self.ha is None:
            return None
        return self.ha.verify(f"{self.BASE}/searchDomainOverride")

    def _record(
        self, action: str, target: str, result: str,
        timer: TimedAction, detail: str = "",
    ) -> AuditEntry:
        entry = AuditEntry.now(
            user=self.actor, action=action, target=target,
            host=self.host_name, result=result,
            duration_ms=timer.elapsed_ms, detail=detail,
        )
        try:
            self.audit.append(entry)
        except OSError as e:
            log.warning("audit log write failed: %s", e)
        return entry
