"""OPNsense HTTP client — scaffold.

Real implementation lands in v1.0.0. Keep this stub typed and importable so
collectors/writers can be wired in parallel.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class OPNsenseHost:
    name: str
    url: str
    api_key: str
    api_secret: str
    verify_tls: bool = True
    ca_bundle_path: str | None = None


class OPNsenseClient:
    """HTTPS client against /api/<module>/<controller>/<action>.

    Wire in v1:
      - Auth: HTTP Basic with (api_key, api_secret).
      - Retries: exponential, 3 attempts on idempotent GETs only.
      - Timeouts: 5s default.
      - Concurrency: per-host soft cap 4 req/s.
    """

    def __init__(self, host: OPNsenseHost) -> None:
        self.host = host

    def get(self, path: str, **params: Any) -> dict[str, Any]:
        raise NotImplementedError('wire in v1.0.0')

    def post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        raise NotImplementedError('wire in v1.0.0')
