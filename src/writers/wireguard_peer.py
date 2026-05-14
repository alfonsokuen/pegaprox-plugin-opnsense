"""WireGuard peer (client) CRUD writer.

Endpoints (`/api/wireguard/client/*`) follow the same shape as filter rules:
addClient / setClient / delClient / searchClient, with `service/reconfigure`
to commit. Verified live against OPNsense 26.1.2 (2026-05-10):
addClient → uuid → delClient round-trip OK.

OPNsense uses "client" terminology for what WireGuard upstream calls a "peer".
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
class WireguardPeerInput:
    name: str               # human label
    pubkey: str             # base64 32-byte public key (44 chars w/ padding)
    tunneladdress: str      # CIDR e.g. "10.99.0.5/32"
    keepalive: int = 25     # PersistentKeepalive seconds (0 = disabled)
    psk: str = ""           # pre-shared key, optional
    enabled: bool = True

    def to_payload(self) -> dict[str, Any]:
        body = {
            "client": {
                "enabled": "1" if self.enabled else "0",
                "name": self.name,
                "pubkey": self.pubkey,
                "tunneladdress": self.tunneladdress,
                "keepalive": str(self.keepalive),
            }
        }
        if self.psk:
            body["client"]["psk"] = self.psk
        return body


WireguardPeerResult = AliasResult
wireguard_peer_result_to_dict = alias_result_to_dict


class WireguardPeerWriter:
    BASE = "/api/wireguard/client"
    APPLY = "/api/wireguard/service/reconfigure"

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
        # OPNsense exposes searchClient as POST in some builds; we tolerate both.
        try:
            out = self.client.get(f"{self.BASE}/searchClient")
        except OPNsenseError:
            out = self.client.post(f"{self.BASE}/searchClient", {})
        return out.get("rows", []) if isinstance(out, dict) else []

    def get(self, uuid: str) -> dict[str, Any]:
        return self.client.get(f"{self.BASE}/getClient/{uuid}")

    def create(self, payload: WireguardPeerInput) -> WireguardPeerResult:
        self._validate(payload)
        with TimedAction() as t:
            try:
                resp = self.client.post(f"{self.BASE}/addClient", payload.to_payload())
            except OPNsenseError as e:
                self._record("wgpeer.create", payload.name or "?", "error", t, str(e))
                return WireguardPeerResult(ok=False, detail=str(e))
            uuid = str(resp.get("uuid", ""))
            if not uuid:
                self._record("wgpeer.create", payload.name, "error", t, "no uuid in response")
                return WireguardPeerResult(ok=False, detail="OPNsense did not return uuid")
            try:
                self._apply()
            except OPNsenseError as e:
                try:
                    self.client.post(f"{self.BASE}/delClient/{uuid}", {})
                except OPNsenseError:
                    pass
                self._record("wgpeer.create", payload.name, "error", t, f"apply failed → rolled back: {e}")
                return WireguardPeerResult(ok=False, detail=f"apply failed → rolled back: {e}")
        sync = self._maybe_sync()
        entry = self._record("wgpeer.create", uuid, "ok", t, payload.name, payload_sha256=hash_payload(payload.to_payload()))
        return WireguardPeerResult(ok=True, uuid=uuid, sync=sync, audit=entry)

    def delete(self, uuid: str) -> WireguardPeerResult:
        with TimedAction() as t:
            try:
                self.client.post(f"{self.BASE}/delClient/{uuid}", {})
                self._apply()
            except OPNsenseError as e:
                self._record("wgpeer.delete", uuid, "error", t, str(e))
                return WireguardPeerResult(ok=False, uuid=uuid, detail=str(e))
        sync = self._maybe_sync()
        entry = self._record("wgpeer.delete", uuid, "ok", t)
        return WireguardPeerResult(ok=True, uuid=uuid, sync=sync, audit=entry)

    def _validate(self, payload: WireguardPeerInput) -> None:
        if not payload.name:
            raise ValueError("name is required")
        # Public key: base64-encoded 32 bytes => 44 chars including padding.
        if not payload.pubkey or len(payload.pubkey) != 44 or not payload.pubkey.endswith("="):
            raise ValueError("pubkey must be a 44-char base64-encoded WireGuard public key")
        if not payload.tunneladdress or "/" not in payload.tunneladdress:
            raise ValueError("tunneladdress must be CIDR (e.g. 10.99.0.5/32)")
        if payload.keepalive < 0 or payload.keepalive > 65535:
            raise ValueError("keepalive must be 0..65535 seconds")

    def _apply(self) -> None:
        self.client.post(self.APPLY, {})

    def _maybe_sync(self) -> SyncResult | None:
        if self.ha is None:
            return None
        return self.ha.verify_robust(f"{self.BASE}/searchClient")

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
