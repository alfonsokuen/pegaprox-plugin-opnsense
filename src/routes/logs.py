"""Firewall log endpoint — paginated tail.

Returns the most recent N entries (default 100, capped at 500). Caller
can pass `limit` as a query string param.
"""
from __future__ import annotations

import logging
from typing import Any

from src.client import (
    OPNsenseAuthError,
    OPNsenseClient,
    OPNsenseError,
    OPNsenseHost,
    OPNsenseTimeoutError,
)
from src.collectors import collect_firewall_log

log = logging.getLogger(__name__)

DEFAULT_LIMIT = 100
MAX_LIMIT = 500


def _clamp_limit(raw: object) -> int:
    try:
        n = int(str(raw))
    except (TypeError, ValueError):
        return DEFAULT_LIMIT
    if n <= 0:
        return DEFAULT_LIMIT
    return min(n, MAX_LIMIT)


def build_logs_payload(host: OPNsenseHost, limit: object = DEFAULT_LIMIT) -> tuple[int, dict[str, Any]]:
    n = _clamp_limit(limit)
    client = OPNsenseClient(host)
    try:
        rows = collect_firewall_log(client, limit=n)
        return 200, {"ok": True, "data": {"limit": n, "entries": rows}}
    except OPNsenseAuthError as e:
        return 401, {"ok": False, "error": "auth", "detail": str(e)}
    except OPNsenseTimeoutError as e:
        return 504, {"ok": False, "error": "timeout", "detail": str(e)}
    except OPNsenseError as e:
        log.exception("logs failed")
        return 502, {"ok": False, "error": "upstream", "detail": str(e)}
