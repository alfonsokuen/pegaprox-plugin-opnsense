"""Append-only audit log for plugin write operations.

JSONL on disk: each line is a self-contained JSON object so the file can
grow without rotation strategy and `tail -f` works the way you'd expect.

Shape:
    {
      "ts": "2026-05-10T17:42:01Z",
      "user": "<auth identity from PegaProx>",
      "action": "alias.create",
      "target": "<uuid or name>",
      "host": "<OPNsense host name>",
      "result": "ok|error",
      "duration_ms": 412,
      "detail": "...optional message..."
    }

Sensitive payloads (rule contents, IP lists, peer keys) are NOT logged.
The brief calls for hash + diff, but for v0.6.0 we ship the metadata-only
record. Adding payload hashes is a v0.7+ task once the writer set is wider.
"""
from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Iterable


def _utc_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


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
                out.append(AuditEntry(**d))
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
                out.append(AuditEntry(**json.loads(ln)))
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
