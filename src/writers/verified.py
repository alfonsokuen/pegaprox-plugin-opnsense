"""Verified CRUD for management routes; never retry a mutation.

Readback verifies stored configuration, not packet delivery. HA verification
checks the same object and requested fields on the actual configured peer.
"""
from __future__ import annotations

import re
import threading
import time
from dataclasses import asdict
from typing import Any
from uuid import UUID

from src.client import OPNsenseAuthError, OPNsenseError, OPNsenseTimeoutError

from .audit import AuditEntry, hash_payload

SPECS = {
    "port_forward": ("/api/firewall/d_nat", "Rule", "rule", "apply"),
    "rules": ("/api/firewall/filter", "Rule", "rule", "apply"),
    "aliases": ("/api/firewall/alias", "Item", "alias", "reconfigure"),
}
_LOCKS_GUARD = threading.Lock()
_WRITE_LOCKS: dict[tuple[str, str], Any] = {}
DEFAULT_HA_VERIFY_ATTEMPTS = 6
DEFAULT_HA_VERIFY_BACKOFF = 0.5


def validate_revision(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError("revision must be the 64-character revision returned by the latest listing")
    return value


def validate_uuid(value: Any) -> str:
    if not isinstance(value, str):
        raise TypeError("uuid must be a UUID string")
    try:
        if str(UUID(value)) != value.lower():
            raise ValueError()
    except (ValueError, AttributeError) as exc:
        raise ValueError("uuid must be a canonical UUID") from exc
    return value.lower()


def selected(value: Any) -> Any:
    """Convert OPNsense form option dictionaries back to their stored values."""
    if isinstance(value, dict):
        if value and all(isinstance(v, dict) and "selected" in v for v in value.values()):
            return ",".join(str(k) for k, v in value.items() if str(v["selected"]) == "1")
        return {k: selected(v) for k, v in value.items()}
    return value


def _flatten(value: dict, prefix: str = "") -> dict:
    result = {}
    for key, val in value.items():
        name = prefix + key
        if isinstance(val, dict):
            result.update(_flatten(val, name + "."))
        else:
            result[name] = "" if val is None else str(val)
    return result


def matches(actual: dict, expected: dict) -> bool:
    actual_flat, expected_flat = _flatten(selected(actual)), _flatten(expected)
    for key, value in expected_flat.items():
        observed = actual_flat.get(key)
        if observed is None:
            return False
        if key == "protocol":
            observed, value = observed.lower(), value.lower()
        if key == "content":
            # Alias content is a MultiSelectField on getItem and newline text on write.
            observed = sorted(observed.replace("\n", ",").split(","))
            value = sorted(value.replace("\n", ",").split(","))
        if observed != value:
            return False
    return True


class Rejected(OPNsenseError):
    def __init__(self, detail: str, validations: Any = None):
        super().__init__(detail)
        self.validations = validations


class Conflict(OPNsenseError):
    """The form was based on an obsolete object revision."""


def require_success(response: Any, operation: str) -> dict:
    if not isinstance(response, dict):
        raise Rejected(f"{operation}: invalid API response")
    if response.get("validations"):
        raise Rejected(f"{operation}: OPNsense rejected validation", response["validations"])
    markers = [str(response[k]).strip().lower() for k in ("result", "status") if k in response]
    if not markers or any(v not in ("ok", "saved", "deleted", "done", "success") for v in markers):
        raise Rejected(f"{operation}: OPNsense did not acknowledge success")
    return response


class VerifiedFirewallWriter:
    def __init__(self, client, audit, resource: str, actor="plugin", peer=None,
                 ha_verify_attempts=DEFAULT_HA_VERIFY_ATTEMPTS,
                 ha_verify_backoff=DEFAULT_HA_VERIFY_BACKOFF):
        if isinstance(ha_verify_attempts, bool) or not isinstance(ha_verify_attempts, int) or not 1 <= ha_verify_attempts <= 10:
            raise ValueError("ha_verify_attempts must be an integer between 1 and 10")
        if isinstance(ha_verify_backoff, bool) or not isinstance(ha_verify_backoff, (int, float)) or not 0 <= ha_verify_backoff <= 2:
            raise ValueError("ha_verify_backoff must be a number between 0 and 2 seconds")
        self.ha_verify_attempts = ha_verify_attempts
        self.ha_verify_backoff = ha_verify_backoff
        self.client, self.audit, self.resource, self.actor, self.peer = client, audit, resource, actor, peer
        self.base, self.suffix, self.key, self.apply_name = SPECS[resource]

    def search(self, client=None) -> list[dict]:
        out = (client or self.client).get(f"{self.base}/search{self.suffix}", rowCount=-1, current=1)
        if not isinstance(out, dict) or not isinstance(out.get("rows"), list):
            raise OPNsenseError("search: invalid API response (rows missing)")
        if any(not isinstance(row, dict) for row in out["rows"]):
            raise OPNsenseError("search: invalid row")
        if "total" in out and int(out["total"]) > len(out["rows"]):
            raise OPNsenseError("search: incomplete response; refusing partial verification")
        return out["rows"]

    def get(self, uuid: str, client=None) -> dict:
        out = (client or self.client).get(f"{self.base}/get{self.suffix}/{uuid}")
        if not isinstance(out, dict) or not isinstance(out.get(self.key), dict) or not out[self.key]:
            raise OPNsenseError("readback: requested object missing or invalid")
        return selected(out[self.key])

    def verify(self, uuid: str, expected: dict | None, client=None) -> bool:
        if expected is None:
            return not any(str(row.get("uuid", "")).lower() == uuid.lower() for row in self.search(client))
        return matches(self.get(uuid, client), expected)

    def _apply(self):
        require_success(self.client.post(f"{self.base}/{self.apply_name}", {}), "apply")

    def _sync(self, uuid, expected):
        if self.peer is None:
            return None
        result = {"triggered": False, "mode": "automatic", "verified": False, "attempts": 0, "detail": ""}
        # OPNsense propagates configured XMLRPC sections during apply.
        # Core has no syncTo action. Forcing restart_all would restart
        # unrelated peer services, so only observe real convergence here.
        # Defaults allow 7.5 seconds of accumulated waits across six reads.
        # Network request durations are additional; this is not a hard deadline.
        # One evolving operation result; repeated keys track its latest state, not N rows.
        for attempt in range(1, self.ha_verify_attempts + 1):  # nosemgrep: idk-constant-key-in-loop-py
            # Progress counter, not a collection keyed by individual attempts.
            result.update(attempts=attempt)
            try:
                if self.verify(uuid, expected, self.peer):
                    result.update(verified=True, detail="Peer configuration verified")
                    return result
                result["detail"] = "Peer configuration did not converge"
            except OPNsenseError as exc:
                result["detail"] = str(exc)
            if attempt < self.ha_verify_attempts:
                time.sleep(self.ha_verify_backoff * attempt)
        return result

    def execute(self, action: str, payload: dict | None = None, uuid: str = "", revision: str = "") -> dict:
        if action != "create":
            uuid = validate_uuid(uuid)
            validate_revision(revision)
        # Serialize this process's writers through the final read/compare/write.
        # OPNsense has no conditional mutation API: an external actor can still
        # write between the read and POST, which cannot be made atomic here.
        lock_key = (getattr(self.client.host, "url", self.client.host.name), self.resource)
        with _LOCKS_GUARD:
            lock = _WRITE_LOCKS.setdefault(lock_key, threading.Lock())
        with lock:
            return self._execute(action, payload, uuid, revision)

    def _execute(self, action: str, payload: dict | None, uuid: str, revision: str) -> dict:
        started = time.monotonic()
        result = {"ok": False, "uuid": uuid, "action": action, "detail": "",
                  "verified": False, "applied": False, "sync": None,
                  "rollback": {"attempted": False, "verified": False, "local_verified": False,
                               "peer_verified": None, "detail": "Not required"},
                  "audit": None}
        accepted = False
        expected = payload[self.key] if payload else None
        try:
            # Reserve durable evidence before touching the firewall.
            self.audit.append(AuditEntry.now(user=self.actor, action=f"{self.resource}.{action}",
                target=uuid, host=self.client.host.name, result="started", duration_ms=0,
                payload_sha256=hash_payload(payload)))
            if action != "create":
                current = self.get(uuid)
                if hash_payload(current) != revision:
                    raise Conflict("Configuration changed since it was loaded; refresh before editing or deleting")
            verb = {"create": "add", "update": "set", "delete": "del"}[action]
            path = f"{self.base}/{verb}{self.suffix}" + (f"/{uuid}" if uuid else "")
            response = require_success(self.client.post(path, payload or {}), action)
            if action == "create":
                try:
                    uuid = validate_uuid(response.get("uuid"))
                except (ValueError, TypeError) as exc:
                    raise OPNsenseError("Create acknowledged without valid UUID; reconcile manually") from exc
                result["uuid"] = uuid
            accepted = True
            self._apply()
            result["applied"] = True
            if not self.verify(uuid, expected):
                raise OPNsenseError("Readback does not match requested configuration")
            result["verified"] = True
            result["sync"] = self._sync(uuid, expected)
            result["ok"] = result["sync"] is None or result["sync"]["verified"]
            if not result["ok"]:
                result.update(error="ha_unverified", detail="Saved locally; HA verification failed")
        except (OPNsenseError, OSError) as exc:
            error = "conflict" if isinstance(exc, Conflict) else "auth" if isinstance(exc, OPNsenseAuthError) else "timeout" if isinstance(exc, OPNsenseTimeoutError) else "validation" if isinstance(exc, Rejected) and exc.validations else "upstream"
            result.update(error=error, detail=str(exc))
            if isinstance(exc, Rejected) and exc.validations:
                result["validations"] = exc.validations
            result["rollback"]["detail"] = "Not attempted; inspect current configuration before retrying"
            # Only undo a known create after a definite rejection. A timeout may
            # already have applied successfully; never blindly reverse or retry it.
            if accepted and action == "create" and isinstance(exc, Rejected):
                rollback = result["rollback"]
                rollback["attempted"] = True
                try:
                    require_success(self.client.post(f"{self.base}/del{self.suffix}/{uuid}", {}), "rollback delete")
                    self._apply()
                    rollback["local_verified"] = self.verify(uuid, None)
                    peer_result = self._sync(uuid, None)
                    rollback["peer_verified"] = None if peer_result is None else peer_result["verified"]
                    rollback["verified"] = rollback["local_verified"] and (self.peer is None or rollback["peer_verified"] is True)
                    rollback["detail"] = "Deleted and applied; absence verified on all configured nodes" if rollback["verified"] else "Rollback absence not verified on all configured nodes"
                    if peer_result is not None:
                        rollback["detail"] += "; peer: " + peer_result["detail"]
                except OPNsenseError as rollback_error:
                    rollback["detail"] = str(rollback_error)
        entry = AuditEntry.now(user=self.actor, action=f"{self.resource}.{action}", target=uuid,
            host=self.client.host.name, result="ok" if result["ok"] else "error",
            duration_ms=int((time.monotonic() - started) * 1000),
            detail=result["detail"] + ("; rollback=" + str(result["rollback"]) if result["rollback"]["attempted"] else ""),
            payload_sha256=hash_payload(payload))
        try:
            self.audit.append(entry)
            result["audit"] = asdict(entry)
        except OSError:
            result.update(ok=False, error="audit", detail=result["detail"] + "; audit persistence failed")
        return result
