"""Verified CRUD for management routes; never retry a mutation.

Readback verifies stored configuration, not packet delivery. HA verification
checks the same object and requested fields on the actual configured peer.
"""
from __future__ import annotations

import re
import ipaddress
import threading
import time
from dataclasses import asdict
from typing import Any
from uuid import UUID
from urllib.parse import urlsplit

from src.client import OPNsenseAuthError, OPNsenseError, OPNsenseTimeoutError
from src.collectors.carp import collect_carp_status

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


class UnsafeSync(OPNsenseError):
    """The configured XMLRPC direction or scope cannot be confirmed."""


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
                 ha_verify_backoff=DEFAULT_HA_VERIFY_BACKOFF, ha_sync_mode="automatic"):
        if ha_sync_mode not in ("automatic", "xmlrpc_pf"):
            raise ValueError("ha_sync_mode must be automatic or xmlrpc_pf")
        self.ha_sync_mode = ha_sync_mode
        self._sync_plan = None
        self._peer_delete_revision = None
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
        count = sum(not (self.resource == "port_forward" and re.fullmatch(r"lockout_\d+", str(row.get("uuid", ""))))
                    for row in out["rows"])
        # DNatController prepends generated lockout rows without adding them to total.
        if "total" in out and int(out["total"]) > count:
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

    def _sync_preflight(self):
        if self.peer is None or self.ha_sync_mode != "xmlrpc_pf":
            return
        local_data = self.client.get("/api/core/hasync/get")
        peer_data = self.peer.get("/api/core/hasync/get")
        if not isinstance(local_data, dict) or not isinstance(peer_data, dict):
            raise UnsafeSync("Cannot verify XMLRPC configuration")
        local = selected(local_data).get("hasync", {})
        peer = selected(peer_data).get("hasync", {})
        if (not isinstance(local, dict) or not isinstance(peer, dict)
                or not isinstance(peer.get("synchronizetoip"), str)):
            raise UnsafeSync("Cannot verify XMLRPC configuration")
        required = {"aliases": "aliases", "rules": "rules", "port_forward": "nat"}[self.resource]
        sections = set(str(local.get("syncitems", "")).split(","))
        if required not in sections or not sections <= {"aliases", "rules", "nat"}:
            raise UnsafeSync("XMLRPC must select the required section and only aliases, rules and NAT")
        if peer.get("synchronizetoip"):
            raise UnsafeSync("XMLRPC must be configured in one direction only")
        target = local.get("synchronizetoip", "")
        try:
            if "://" in target:
                parsed = urlsplit(target)
                if (parsed.scheme != "https" or parsed.username is not None or parsed.password is not None
                        or parsed.path not in ("", "/") or parsed.query or parsed.fragment):
                    raise ValueError()
                if parsed.port is not None and not 1 <= parsed.port <= 65535:
                    raise ValueError()
                target = parsed.hostname
            address = ipaddress.ip_address(target)
            if address.is_loopback or address.is_unspecified or address.is_multicast:
                raise ValueError()
        except (ValueError, TypeError):
            raise UnsafeSync("XMLRPC target must be a literal peer IP or HTTPS IP URL") from None

        def addresses(client):
            config = client.get("/api/diagnostics/interface/getInterfaceConfig")
            result = set()
            if not isinstance(config, dict):
                raise UnsafeSync("Cannot verify XMLRPC peer interfaces")
            for interface in config.values():
                if not isinstance(interface, dict):
                    continue
                for family in ("ipv4", "ipv6"):
                    entries = interface.get(family, [])
                    if not isinstance(entries, list):
                        raise UnsafeSync("Cannot verify XMLRPC peer interfaces")
                    for entry in entries:
                        if isinstance(entry, dict) and not entry.get("vhid"):
                            try:
                                result.add(ipaddress.ip_address(entry.get("ipaddr")))
                            except (ValueError, TypeError):
                                continue
            return result

        if address not in addresses(self.peer) or address in addresses(self.client):
            raise UnsafeSync("XMLRPC target is not an exclusive address of the configured peer")
        left, right = collect_carp_status(self.client), collect_carp_status(self.peer)
        identities = []
        for status, role in ((left, "MASTER"), (right, "BACKUP")):
            vips = status["vhids"]
            if (not status["enabled"] or status["maintenance_mode"] or not vips
                    or any(v["status"] != role for v in vips)):
                raise UnsafeSync("XMLRPC requires the selected node to remain MASTER and its peer BACKUP")
            identities.append({(v["vhid"], v["ipaddr"]) for v in vips})
        if identities[0] != identities[1]:
            raise UnsafeSync("XMLRPC nodes must own the same CARP VIPs")
        return (local.get("synchronizetoip"), tuple(sorted(sections)), tuple(sorted(identities[0])))

    def _sync(self, uuid, expected):
        if self.peer is None:
            return None
        result = {"triggered": False, "mode": self.ha_sync_mode, "verified": False, "attempts": 0, "detail": ""}
        # 26.1.2 apply only reloads locally. Explicit mode synchronizes the
        # preflighted firewall sections and reloads peer PF, never restartAll.
        # An ambiguous sync must not trigger rollback of an applied create.
        if self.ha_sync_mode == "xmlrpc_pf":
            try:
                if self._sync_preflight() != self._sync_plan:
                    raise UnsafeSync("XMLRPC configuration changed during the operation; reconcile manually")
                result["triggered"] = True
                require_success(self.client.post("/api/core/hasync_status/restart/pf", {}), "HA sync")
            except OPNsenseError as exc:
                result["detail"] = str(exc)
                return result
        # Automatic mode only observes independently configured synchronization.
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
        if expected is None and self._peer_delete_revision is not None:
            self._finish_last_dnat_delete(uuid, result)
        return result

    def _dnat_ids(self, client=None):
        ids = set()
        for row in self.search(client):
            value = row.get("uuid")
            # 26.1.2 exposes generated anti-lockout rows in the DNAT grid.
            if isinstance(value, str) and re.fullmatch(r"lockout_\d+", value):
                continue
            try:
                ids.add(validate_uuid(value))
            except (ValueError, TypeError):
                raise UnsafeSync("Unknown DNAT row; cannot qualify last-rule cleanup") from None
        return ids

    def _finish_last_dnat_delete(self, uuid, result):
        """26.1.2 XMLRPC merge preserves nat/rule when its last row is absent."""
        cleanup = {"attempted": False, "deleted": False, "applied": False, "verified": False}
        result["peer_cleanup"] = cleanup
        try:
            if (self._sync_preflight() != self._sync_plan or self._dnat_ids()
                    or self._dnat_ids(self.peer) != {uuid}):
                raise UnsafeSync("HA or local DNAT changed; peer cleanup requires reconciliation")
            if hash_payload(self.get(uuid, self.peer)) != self._peer_delete_revision:
                raise Conflict("Peer DNAT changed; refusing peer cleanup")
            self.audit.append(AuditEntry.now(user=self.actor, action="port_forward.peer_delete",
                target=uuid, host=self.peer.host.name, result="started", duration_ms=0,
                payload_sha256=self._peer_delete_revision))
            cleanup["attempted"] = True
            require_success(self.peer.post(f"{self.base}/del{self.suffix}/{uuid}", {}), "peer delete")
            cleanup["deleted"] = True
            require_success(self.peer.post(f"{self.base}/{self.apply_name}", {}), "peer apply")
            cleanup["applied"] = True
            cleanup["verified"] = self.verify(uuid, None) and self.verify(uuid, None, self.peer)
            result.update(verified=cleanup["verified"], detail="Last DNAT absence verified on both nodes"
                          if cleanup["verified"] else "Peer cleanup absence unverified")
        except (OPNsenseError, OSError) as exc:
            result["detail"] = str(exc)

    def execute(self, action: str, payload: dict | None = None, uuid: str = "", revision: str = "") -> dict:
        if action != "create":
            uuid = validate_uuid(uuid)
            validate_revision(revision)
        # Serialize this process's writers through the final read/compare/write.
        # OPNsense has no conditional mutation API: an external actor can still
        # write between the read and POST, which cannot be made atomic here.
        local_key = getattr(self.client.host, "url", self.client.host.name)
        peer_key = getattr(self.peer.host, "url", self.peer.host.name) if self.peer else ""
        lock_key = tuple(sorted((local_key, peer_key)))
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
        self._peer_delete_revision = None
        expected = payload[self.key] if payload else None
        try:
            # Reserve durable evidence before touching the firewall.
            self.audit.append(AuditEntry.now(user=self.actor, action=f"{self.resource}.{action}",
                target=uuid, host=self.client.host.name, result="started", duration_ms=0,
                payload_sha256=hash_payload(payload)))
            self._sync_plan = self._sync_preflight()
            if action != "create":
                current = self.get(uuid)
                if hash_payload(current) != revision:
                    raise Conflict("Configuration changed since it was loaded; refresh before editing or deleting")
                if (action == "delete" and self.resource == "port_forward" and self.peer is not None
                        and self.ha_sync_mode == "xmlrpc_pf" and self._dnat_ids() == {uuid}):
                    peer_revision = hash_payload(self.get(uuid, self.peer))
                    if peer_revision != revision or self._dnat_ids(self.peer) != {uuid}:
                        raise Conflict("Last DNAT differs on peer; reconcile before deleting")
                    self._peer_delete_revision = peer_revision
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
            error = "ha_unsafe" if isinstance(exc, UnsafeSync) else "conflict" if isinstance(exc, Conflict) else "auth" if isinstance(exc, OPNsenseAuthError) else "timeout" if isinstance(exc, OPNsenseTimeoutError) else "validation" if isinstance(exc, Rejected) and exc.validations else "upstream"
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
            detail=result["detail"] + ("; rollback=" + str(result["rollback"]) if result["rollback"]["attempted"] else "")
                + ("; peer_cleanup=" + str(result["sync"]["peer_cleanup"])
                   if result["sync"] and "peer_cleanup" in result["sync"] else ""),
            payload_sha256=hash_payload(payload))
        try:
            self.audit.append(entry)
            result["audit"] = asdict(entry)
        except OSError:
            result.update(ok=False, error="audit", detail=result["detail"] + "; audit persistence failed")
        return result
