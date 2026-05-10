"""Append-only audit log for plugin write operations.

JSONL on disk: each line is a self-contained JSON object so the file can
grow without rotation strategy and `tail -f` works the way you'd expect.

Shape (v1.9.0+):
    {
      "ts": "2026-05-10T17:42:01Z",
      "user": "<auth identity from PegaProx>",
      "action": "alias.create",
      "target": "<uuid or name>",
      "host": "<OPNsense host name>",
      "result": "ok|error",
      "duration_ms": 412,
      "detail": "...optional message...",
      "payload_sha256": "<hex sha256 of canonical-JSON payload, or ''>"
    }

Sensitive payloads (rule contents, IP lists, peer keys) are NOT logged
verbatim — only a tamper-evident SHA256 hash of the canonical-JSON shape
sent to OPNsense. The hash lets an auditor replay a known input and
verify a historical write referenced that exact payload, without leaking
secrets through the JSONL trail.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable


def _utc_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def hash_payload(payload: Any) -> str:
    """SHA256 hex of canonical-JSON (sorted keys, no whitespace) of the payload.

    Used by writers to record a tamper-evident hash of the exact body sent to
    OPNsense, without leaking the sensitive contents into the audit log.
    """
    if payload is None:
        return ""
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class AuditEntry:
    ts: str
    user: str
    action: str
    target: str
    host: str
    result: str
    duration_ms: int
    detail: str = ""
    payload_sha256: str = ""

    @classmethod
    def now(
        cls,
        *,
        user: str,
        action: str,
        target: str,
        host: str,
        result: str,
        duration_ms: int,
        detail: str = "",
        payload_sha256: str = "",
    ) -> "AuditEntry":
        return cls(
            ts=_utc_iso(),
            user=user,
            action=action,
            target=target,
            host=host,
            result=result,
            duration_ms=duration_ms,
            detail=detail,
            payload_sha256=payload_sha256,
        )


class AuditLog:
    """Append-only writer + reader for the JSONL log."""

    def __init__(self, path: str) -> None:
        self.path = path
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)

    def append(self, entry: AuditEntry) -> None:
        line = json.dumps(asdict(entry), ensure_ascii=False, separators=(",", ":"))
        with self._lock:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(line + "\n")

    def tail(self, limit: int = 100) -> list[AuditEntry]:
        if not os.path.exists(self.path):
            return []
        with self._lock:
            with open(self.path, "r", encoding="utf-8") as f:
                lines = f.readlines()[-int(limit):]
        out: list[AuditEntry] = []
        for ln in lines:
            ln = ln.strip()
            if not ln:
                continue
            try:
                d = json.loads(ln)
                # tolerate unknown keys from future schema versions
                known = {f for f in AuditEntry.__dataclass_fields__}
                out.append(AuditEntry(**{k: v for k, v in d.items() if k in known}))
            except (json.JSONDecodeError, TypeError):
                continue
        return out

    def iter_all(self) -> Iterable[AuditEntry]:
        if not os.path.exists(self.path):
            return iter(())
        with self._lock:
            with open(self.path, "r", encoding="utf-8") as f:
                payload = f.read()
        out: list[AuditEntry] = []
        for ln in payload.splitlines():
            ln = ln.strip()
            if not ln:
                continue
            try:
                d = json.loads(ln)
                known = {f for f in AuditEntry.__dataclass_fields__}
                out.append(AuditEntry(**{k: v for k, v in d.items() if k in known}))
            except (json.JSONDecodeError, TypeError):
                continue
        return iter(out)


# Convenience -----------------------------------------------------------------

@dataclass
class TimedAction:
    """Stopwatch wrapper used by writers around the OPNsense calls.

    Usage:
        with TimedAction() as t:
            client.post(...)
        log.append(AuditEntry.now(..., duration_ms=t.elapsed_ms, ...))
    """

    started_at: float = field(default_factory=time.monotonic)
    elapsed_ms: int = 0

    def __enter__(self) -> "TimedAction":
        self.started_at = time.monotonic()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.elapsed_ms = int((time.monotonic() - self.started_at) * 1000)
