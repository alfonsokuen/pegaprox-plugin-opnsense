"""HA sync trigger + post-sync verification.

`/api/core/hasync/syncTo` accepts an empty body and instructs the local
node to push its config to the configured peer. We then re-fetch the
relevant section on the peer and compare a structural fingerprint.

If the peer client is omitted, `verify` short-circuits to `True` — the
caller is expected to treat that as "single-node, no HA in scope".
"""
from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass
from typing import Any

from src.client import OPNsenseClient

log = logging.getLogger(__name__)


def _fingerprint(payload: Any) -> str:
    blob = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()[:16]


@dataclass(frozen=True)
class SyncResult:
    triggered: bool
    verified: bool
    local_fingerprint: str
    peer_fingerprint: str
    detail: str = ""


class HAVerifier:
    """Triggers a sync and confirms the peer reflects the new state."""

    def __init__(
        self,
        local: OPNsenseClient,
        peer: OPNsenseClient | None = None,
    ) -> None:
        self.local = local
        self.peer = peer

    def sync(self) -> bool:
        try:
            self.local.post("/api/core/hasync/syncTo", payload={})
            return True
        except Exception as e:  # pragma: no cover - exercised in live tests
            log.warning("hasync syncTo failed: %s", e)
            return False

    def verify(self, search_path: str) -> SyncResult:
        """Triggers sync, reads back from local + peer, compares fingerprints.

        `search_path` is e.g. "/api/firewall/alias/searchItem".
        """
        local_payload = self.local.get(search_path)
        local_fp = _fingerprint(local_payload)

        if self.peer is None:
            return SyncResult(
                triggered=False,
                verified=True,
                local_fingerprint=local_fp,
                peer_fingerprint=local_fp,
                detail="no peer configured — single-node mode",
            )

        triggered = self.sync()
        if not triggered:
            return SyncResult(
                triggered=False,
                verified=False,
                local_fingerprint=local_fp,
                peer_fingerprint="",
                detail="syncTo failed",
            )

        try:
            peer_payload = self.peer.get(search_path)
        except Exception as e:
            return SyncResult(
                triggered=True,
                verified=False,
                local_fingerprint=local_fp,
                peer_fingerprint="",
                detail=f"peer fetch failed: {e}",
            )
        peer_fp = _fingerprint(peer_payload)

        return SyncResult(
            triggered=True,
            verified=(local_fp == peer_fp),
            local_fingerprint=local_fp,
            peer_fingerprint=peer_fp,
        )
