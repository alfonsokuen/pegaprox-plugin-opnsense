"""HA sync trigger + post-sync verification.

`/api/core/hasync/syncTo` accepts an empty body and instructs the local
node to push its config to the configured peer. We then re-fetch the
relevant section on the peer and compare a structural fingerprint.

If the peer client is omitted, every verify path short-circuits to
`verified=True` — the caller treats that as "single-node, no HA in scope".

v1.14.0 adds two robustness paths over the legacy list-fingerprint check:

- `verify_item(search_path, uuid_field, uuid_value, ...)` — confirms that
  the specific UUID just written appears (or, for deletes, is gone) on the
  peer. Retries with linear backoff to tolerate pfSync propagation lag.
- `verify_revision(...)` — captures `config_revision` from both nodes and
  retries until they match. Catches the failure mode where `syncTo` returns
  200 but the peer never actually updates (brief §9).

The legacy `verify(path)` is preserved verbatim for v1.13.x callers.
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any

from src.client import OPNsenseClient

log = logging.getLogger(__name__)


_SYSINFO_PATH = "/api/diagnostics/system/system_information"


def _fingerprint(payload: Any) -> str:
    blob = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()[:16]


def _iter_rows(payload: Any) -> list[dict]:
    """OPNsense search endpoints return either {'rows': [...]} or a bare list."""
    if isinstance(payload, dict) and isinstance(payload.get("rows"), list):
        return payload["rows"]
    if isinstance(payload, list):
        return payload
    return []


@dataclass(frozen=True)
class SyncResult:
    triggered: bool
    verified: bool
    local_fingerprint: str = ""
    peer_fingerprint: str = ""
    detail: str = ""
    attempts: int = 0
    revision_local: str = ""
    revision_peer: str = ""


class HAVerifier:
    """Triggers a sync and confirms the peer reflects the new state."""

    def __init__(
        self,
        local: OPNsenseClient,
        peer: OPNsenseClient | None = None,
    ) -> None:
        self.local = local
        self.peer = peer

    # ---- sync trigger -------------------------------------------------------

    def sync(self) -> bool:
        try:
            self.local.post("/api/core/hasync/syncTo", payload={})
            return True
        except Exception as e:  # pragma: no cover - exercised in live tests
            log.warning("hasync syncTo failed: %s", e)
            return False

    # ---- legacy list-fingerprint verify (v1.13.x compat) --------------------

    def verify(self, search_path: str) -> SyncResult:
        """Triggers sync, reads back from local + peer, compares fingerprints.

        `search_path` is e.g. "/api/firewall/alias/searchItem".
        """
        local_payload = self.local.get(search_path)
        local_fp = _fingerprint(local_payload)

        if self.peer is None:
            return SyncResult(
                triggered=False, verified=True,
                local_fingerprint=local_fp, peer_fingerprint=local_fp,
                attempts=1, detail="no peer configured — single-node mode",
            )

        triggered = self.sync()
        if not triggered:
            return SyncResult(
                triggered=False, verified=False,
                local_fingerprint=local_fp, attempts=1, detail="syncTo failed",
            )

        try:
            peer_payload = self.peer.get(search_path)
        except Exception as e:
            return SyncResult(
                triggered=True, verified=False,
                local_fingerprint=local_fp, attempts=1,
                detail=f"peer fetch failed: {e}",
            )
        peer_fp = _fingerprint(peer_payload)

        return SyncResult(
            triggered=True, verified=(local_fp == peer_fp),
            local_fingerprint=local_fp, peer_fingerprint=peer_fp,
            attempts=1,
        )

    # ---- v1.14.0: per-UUID verify with retry/backoff ------------------------

    def verify_item(
        self,
        search_path: str,
        uuid_field: str,
        uuid_value: str,
        *,
        expect_present: bool = True,
        max_attempts: int = 5,
        backoff_s: float = 0.4,
    ) -> SyncResult:
        """Confirm a specific row is (or isn't) on the peer after syncTo.

        Retries up to `max_attempts` with linear backoff (`backoff_s * n`) to
        tolerate pfSync propagation lag. Returns as soon as the peer state
        matches the expectation.
        """
        if self.peer is None:
            return SyncResult(
                triggered=False, verified=True, attempts=1,
                detail="no peer configured — single-node mode",
            )

        if not self.sync():
            return SyncResult(
                triggered=False, verified=False, attempts=1,
                detail="syncTo failed",
            )

        last_err: str = ""
        for attempt in range(1, max_attempts + 1):
            try:
                payload = self.peer.get(search_path)
            except Exception as e:
                last_err = str(e)
                if attempt < max_attempts:
                    time.sleep(backoff_s * attempt)
                    continue
                return SyncResult(
                    triggered=True, verified=False, attempts=attempt,
                    detail=f"peer fetch failed: {e}",
                )

            rows = _iter_rows(payload)
            present = any(str(r.get(uuid_field, "")) == uuid_value for r in rows)
            if present == expect_present:
                verb = "found" if expect_present else "removed"
                return SyncResult(
                    triggered=True, verified=True, attempts=attempt,
                    detail=f"{uuid_value} {verb} on peer in {attempt} attempt(s)",
                )

            if attempt < max_attempts:
                time.sleep(backoff_s * attempt)

        verb = "not present" if expect_present else "still present"
        return SyncResult(
            triggered=True, verified=False, attempts=max_attempts,
            detail=f"{uuid_value} {verb} on peer after {max_attempts} attempt(s){' (' + last_err + ')' if last_err else ''}",
        )

    # ---- v1.14.0: combined robust verify ------------------------------------

    def verify_robust(
        self,
        search_path: str,
        *,
        max_attempts: int = 5,
        backoff_s: float = 0.4,
    ) -> SyncResult:
        """Retry list-fingerprint comparison with backoff, then revision check.

        Default verify path for writers that don't know the specific UUID at
        sync time. Returns as soon as fingerprints match; if they never do,
        also returns the revision pair so callers can tell apart "different
        content" from "pfSync didn't propagate".
        """
        local_payload = self.local.get(search_path)
        local_fp = _fingerprint(local_payload)

        if self.peer is None:
            return SyncResult(
                triggered=False, verified=True,
                local_fingerprint=local_fp, peer_fingerprint=local_fp,
                attempts=1, detail="no peer configured — single-node mode",
            )

        if not self.sync():
            return SyncResult(
                triggered=False, verified=False,
                local_fingerprint=local_fp, attempts=1, detail="syncTo failed",
            )

        peer_fp = ""
        last_err = ""
        for attempt in range(1, max_attempts + 1):
            try:
                peer_payload = self.peer.get(search_path)
            except Exception as e:
                last_err = str(e)
                if attempt < max_attempts:
                    time.sleep(backoff_s * attempt)
                    continue
                return SyncResult(
                    triggered=True, verified=False,
                    local_fingerprint=local_fp, attempts=attempt,
                    detail=f"peer fetch failed: {e}",
                )

            peer_fp = _fingerprint(peer_payload)
            if peer_fp == local_fp:
                return SyncResult(
                    triggered=True, verified=True,
                    local_fingerprint=local_fp, peer_fingerprint=peer_fp,
                    attempts=attempt,
                    detail=f"fingerprints matched in {attempt} attempt(s)",
                )

            if attempt < max_attempts:
                time.sleep(backoff_s * attempt)

        # Fingerprints never matched — fetch revisions for diagnostic context.
        rev_l = self._get_revision(self.local)
        rev_p = self._get_revision(self.peer)
        rev_hint = (
            "revision matches but content differs (suspect concurrent write)"
            if rev_l and rev_l == rev_p
            else f"revision mismatch (local={rev_l!r}, peer={rev_p!r})"
        )
        return SyncResult(
            triggered=True, verified=False,
            local_fingerprint=local_fp, peer_fingerprint=peer_fp,
            attempts=max_attempts,
            revision_local=rev_l, revision_peer=rev_p,
            detail=f"fingerprints diverged after {max_attempts} attempt(s); {rev_hint}{' (' + last_err + ')' if last_err else ''}",
        )

    # ---- v1.14.0: config_revision parity ------------------------------------

    def _get_revision(self, client: OPNsenseClient) -> str:
        try:
            data = client.get(_SYSINFO_PATH)
        except Exception as e:
            log.warning("system_information fetch failed: %s", e)
            return ""
        if isinstance(data, dict):
            rev = data.get("config_revision") or data.get("configRevision") or ""
            return str(rev)
        return ""

    def verify_revision(
        self,
        *,
        trigger_sync: bool = True,
        max_attempts: int = 5,
        backoff_s: float = 0.4,
    ) -> SyncResult:
        """Compare `config_revision` on local vs peer until they match.

        Catches the silent-failure mode where `syncTo` returns 200 but the
        peer's running config never advances.
        """
        if self.peer is None:
            return SyncResult(
                triggered=False, verified=True, attempts=1,
                detail="no peer configured — single-node mode",
            )

        if trigger_sync and not self.sync():
            return SyncResult(
                triggered=False, verified=False, attempts=1,
                detail="syncTo failed",
            )

        rev_l = ""
        rev_p = ""
        for attempt in range(1, max_attempts + 1):
            rev_l = self._get_revision(self.local)
            rev_p = self._get_revision(self.peer)
            if rev_l and rev_l == rev_p:
                return SyncResult(
                    triggered=trigger_sync, verified=True, attempts=attempt,
                    revision_local=rev_l, revision_peer=rev_p,
                    detail=f"config_revision {rev_l} matched in {attempt} attempt(s)",
                )
            if attempt < max_attempts:
                time.sleep(backoff_s * attempt)

        return SyncResult(
            triggered=trigger_sync, verified=False, attempts=max_attempts,
            revision_local=rev_l, revision_peer=rev_p,
            detail=f"config_revision mismatch after {max_attempts} attempt(s) (local={rev_l!r}, peer={rev_p!r})",
        )
