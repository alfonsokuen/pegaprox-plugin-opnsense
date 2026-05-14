"""Firewall filter rule CRUD writer.

Endpoints (`/api/firewall/filter/*`) follow the same shape as aliases:
addRule / setRule / delRule / apply, with `apply` instead of `reconfigure`.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from src.client import OPNsenseClient, OPNsenseError

from .alias import AliasResult, alias_result_to_dict  # reuse shape
from .audit import AuditEntry, AuditLog, TimedAction, hash_payload
from .hasync_writer import HAVerifier, SyncResult

log = logging.getLogger(__name__)


_VALID_ACTIONS = ("pass", "block", "reject")
_VALID_DIRECTIONS = ("in", "out")
_VALID_IP_VERSIONS = ("inet", "inet6", "inet46")


@dataclass(frozen=True)
class RuleInput:
    interface: str          # e.g. "wan", "lan"
    action: str = "pass"    # pass|block|reject
    direction: str = "in"   # in|out
    ipprotocol: str = "inet"
    protocol: str = "any"   # tcp|udp|tcp/udp|any
    source_net: str = "any"
    source_port: str = ""
    destination_net: str = "any"
    destination_port: str = ""
    description: str = ""
    enabled: bool = True
    sequence: int = 1       # rule order

    def to_payload(self) -> dict[str, Any]:
        return {
            "rule": {
                "enabled": "1" if self.enabled else "0",
                "sequence": str(self.sequence),
                "action": self.action,
                "direction": self.direction,
                "ipprotocol": self.ipprotocol,
                "protocol": self.protocol,
                "source_net": self.source_net,
                "source_port": self.source_port,
                "destination_net": self.destination_net,
                "destination_port": self.destination_port,
                "interface": self.interface,
                "description": self.description,
            }
        }


# RuleResult is the same shape as AliasResult — re-export for type clarity.
RuleResult = AliasResult
rule_result_to_dict = alias_result_to_dict


class RuleWriter:
    BASE = "/api/firewall/filter"

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

    def create(self, payload: RuleInput) -> RuleResult:
        self._validate(payload)
        with TimedAction() as t:
            try:
                resp = self.client.post(f"{self.BASE}/addRule", payload.to_payload())
            except OPNsenseError as e:
                self._record("rule.create", payload.description or payload.interface, "error", t, str(e))
                return RuleResult(ok=False, detail=str(e))
            uuid = str(resp.get("uuid", ""))
            if not uuid:
                self._record("rule.create", payload.interface, "error", t, "no uuid in response")
                return RuleResult(ok=False, detail="OPNsense did not return uuid")
            try:
                self._apply()
            except OPNsenseError as e:
                try:
                    self.client.post(f"{self.BASE}/delRule/{uuid}", {})
                except OPNsenseError:
                    pass
                self._record("rule.create", payload.interface, "error", t, f"apply failed → rolled back: {e}")
                return RuleResult(ok=False, detail=f"apply failed → rolled back: {e}")
        sync = self._maybe_sync()
        entry = self._record("rule.create", uuid, "ok", t, payload.description, payload_sha256=hash_payload(payload.to_payload()))
        return RuleResult(ok=True, uuid=uuid, sync=sync, audit=entry)

    def update(self, uuid: str, payload: RuleInput) -> RuleResult:
        self._validate(payload)
        with TimedAction() as t:
            try:
                self.client.post(f"{self.BASE}/setRule/{uuid}", payload.to_payload())
                self._apply()
            except OPNsenseError as e:
                self._record("rule.update", uuid, "error", t, str(e))
                return RuleResult(ok=False, uuid=uuid, detail=str(e))
        sync = self._maybe_sync()
        entry = self._record("rule.update", uuid, "ok", t, payload_sha256=hash_payload(payload.to_payload()))
        return RuleResult(ok=True, uuid=uuid, sync=sync, audit=entry)

    def delete(self, uuid: str) -> RuleResult:
        with TimedAction() as t:
            try:
                self.client.post(f"{self.BASE}/delRule/{uuid}", {})
                self._apply()
            except OPNsenseError as e:
                self._record("rule.delete", uuid, "error", t, str(e))
                return RuleResult(ok=False, uuid=uuid, detail=str(e))
        sync = self._maybe_sync()
        entry = self._record("rule.delete", uuid, "ok", t)
        return RuleResult(ok=True, uuid=uuid, sync=sync, audit=entry)

    # ----- internals ---------------------------------------------------

    def _validate(self, payload: RuleInput) -> None:
        if payload.action not in _VALID_ACTIONS:
            raise ValueError(f"action must be one of {_VALID_ACTIONS}, got {payload.action!r}")
        if payload.direction not in _VALID_DIRECTIONS:
            raise ValueError(f"direction must be one of {_VALID_DIRECTIONS}, got {payload.direction!r}")
        if payload.ipprotocol not in _VALID_IP_VERSIONS:
            raise ValueError(f"ipprotocol must be one of {_VALID_IP_VERSIONS}, got {payload.ipprotocol!r}")
        if not payload.interface:
            raise ValueError("interface is required")

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
