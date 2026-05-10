"""Firewall alias CRUD writer.

Endpoints:
- POST /api/firewall/alias/addItem        body: {"alias": {...}}
- POST /api/firewall/alias/setItem/{uuid} body: {"alias": {...}}
- POST /api/firewall/alias/delItem/{uuid} body: {}
- POST /api/firewall/alias/reconfigure    body: {}
- GET  /api/firewall/alias/searchItem
- GET  /api/firewall/alias/getItem/{uuid}

Apply contract: every write must be paired with a `reconfigure` call —
without it OPNsense persists the config but doesn't push it to pf. We
issue the reconfigure here so callers don't have to remember.

Rollback contract: if `reconfigure` (step 3) fails, we attempt to delete
the row we just created (step 2) so the firewall doesn't end up with an
unreferenced alias. Update/delete failures DO NOT auto-rollback — the
caller is the right authority for those reconciliations.
"""
from __future__ import annotations

import logging
from dataclasses import asdict, dataclass, field
from typing import Any

from src.client import OPNsenseClient, OPNsenseError

from .audit import AuditEntry, AuditLog, TimedAction, hash_payload
from .hasync_writer import HAVerifier, SyncResult

log = logging.getLogger(__name__)


# Subset of types that OPNsense accepts. Full list in the docs; we expose
# the common ones and pass anything through verbatim if the caller picks
# something exotic.
_KNOWN_TYPES = ("host", "network", "port", "url", "urltable", "geoip", "external")


@dataclass(frozen=True)
class AliasInput:
    name: str
    type: str = "host"
    content: str = ""           # newline-separated for hosts/networks
    description: str = ""
    enabled: bool = True
    proto: str = ""             # only relevant for some types

    def to_payload(self) -> dict[str, Any]:
        return {
            "alias": {
                "name": self.name,
                "type": self.type,
                "content": self.content,
                "description": self.description,
                "enabled": "1" if self.enabled else "0",
                "proto": self.proto,
            }
        }


@dataclass(frozen=True)
class AliasResult:
    ok: bool
    uuid: str = ""
    detail: str = ""
    sync: SyncResult | None = None
    audit: AuditEntry | None = None


class AliasWriter:
    """Async-free, request-scoped alias writer.

    Construct one per inbound request — there's no shared state besides
    the audit log handle (which is thread-safe internally).
    """

    BASE = "/api/firewall/alias"

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

    # ---------- read helpers --------------------------------------------

    def search(self, phrase: str = "") -> list[dict[str, Any]]:
        params = {"searchPhrase": phrase} if phrase else {}
        out = self.client.get(f"{self.BASE}/searchItem", **params)
        return out.get("rows", []) if isinstance(out, dict) else []

    def get(self, uuid: str) -> dict[str, Any]:
        return self.client.get(f"{self.BASE}/getItem/{uuid}")

    # ---------- write verbs ---------------------------------------------

    def create(self, payload: AliasInput) -> AliasResult:
        if payload.type not in _KNOWN_TYPES:
            log.warning("alias type '%s' not in known set", payload.type)
        with TimedAction() as t:
            try:
                resp = self.client.post(f"{self.BASE}/addItem", payload.to_payload())
            except OPNsenseError as e:
                self._record("alias.create", payload.name, "error", t, str(e))
                return AliasResult(ok=False, detail=str(e))
            uuid = str(resp.get("uuid", ""))
            if not uuid:
                self._record("alias.create", payload.name, "error", t, "no uuid in response")
                return AliasResult(ok=False, detail="OPNsense did not return uuid")
            try:
                self._reconfigure()
            except OPNsenseError as e:
                # Rollback the orphan row before bubbling up.
                try:
                    self.client.post(f"{self.BASE}/delItem/{uuid}", {})
                except OPNsenseError:
                    pass
                self._record("alias.create", payload.name, "error", t, f"reconfigure failed → rolled back: {e}")
                return AliasResult(ok=False, detail=f"reconfigure failed → rolled back: {e}")
        sync = self._maybe_sync()
        entry = self._record("alias.create", payload.name, "ok", t, f"uuid={uuid}", payload_sha256=hash_payload(payload.to_payload()))
        return AliasResult(ok=True, uuid=uuid, sync=sync, audit=entry)

    def update(self, uuid: str, payload: AliasInput) -> AliasResult:
        with TimedAction() as t:
            try:
                self.client.post(f"{self.BASE}/setItem/{uuid}", payload.to_payload())
                self._reconfigure()
            except OPNsenseError as e:
                self._record("alias.update", uuid, "error", t, str(e))
                return AliasResult(ok=False, uuid=uuid, detail=str(e))
        sync = self._maybe_sync()
        entry = self._record("alias.update", uuid, "ok", t, payload.name, payload_sha256=hash_payload(payload.to_payload()))
        return AliasResult(ok=True, uuid=uuid, sync=sync, audit=entry)

    def delete(self, uuid: str) -> AliasResult:
        with TimedAction() as t:
            try:
                self.client.post(f"{self.BASE}/delItem/{uuid}", {})
                self._reconfigure()
            except OPNsenseError as e:
                self._record("alias.delete", uuid, "error", t, str(e))
                return AliasResult(ok=False, uuid=uuid, detail=str(e))
        sync = self._maybe_sync()
        entry = self._record("alias.delete", uuid, "ok", t)
        return AliasResult(ok=True, uuid=uuid, sync=sync, audit=entry)

    # ---------- internals -----------------------------------------------

    def _reconfigure(self) -> None:
        # OPNsense rejects POST without Content-Length — `{}` is the canonical empty body.
        self.client.post(f"{self.BASE}/reconfigure", {})

    def _maybe_sync(self) -> SyncResult | None:
        if self.ha is None:
            return None
        return self.ha.verify(f"{self.BASE}/searchItem")

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


# Re-exports a JSON-ready dict shape (used by routes layer) ---------------

def alias_result_to_dict(res: AliasResult) -> dict[str, Any]:
    return {
        "ok": res.ok,
        "uuid": res.uuid,
        "detail": res.detail,
        "sync": (
            None if res.sync is None
            else {
                "triggered": res.sync.triggered,
                "verified": res.sync.verified,
                "local_fingerprint": res.sync.local_fingerprint,
                "peer_fingerprint": res.sync.peer_fingerprint,
                "detail": res.sync.detail,
            }
        ),
        "audit": None if res.audit is None else asdict(res.audit),
    }


_default_factory = field  # keep `field` referenced so ruff doesn't drop it
