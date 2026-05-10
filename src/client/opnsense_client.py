"""OPNsense HTTP client.

Talks to /api/<module>/<controller>/<action> endpoints over HTTPS using
HTTP Basic auth with (api_key, api_secret).

Design notes
------------
- Idempotent GETs retry with exponential backoff (3 attempts).
- Non-idempotent POSTs do NOT retry — writers must handle reconcile/rollback
  explicitly (see writers/ in v1).
- TLS verification is on by default; disable only for self-signed lab boxes.
- Timeouts default to 5s connect / 10s read.
- Per-host concurrency is intentionally not enforced here; the collector
  layer schedules calls and is the right place for rate limiting.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin

import requests
from requests.auth import HTTPBasicAuth
from requests.exceptions import RequestException

log = logging.getLogger(__name__)


class OPNsenseError(Exception):
    """Raised when the OPNsense API returns an unexpected response."""


class OPNsenseAuthError(OPNsenseError):
    """401/403 from OPNsense — bad credentials or insufficient privileges."""


class OPNsenseTimeoutError(OPNsenseError):
    """Network or read timeout exhausted retries."""


@dataclass(frozen=True)
class OPNsenseHost:
    name: str
    url: str
    api_key: str
    api_secret: str
    verify_tls: bool = True
    ca_bundle_path: str | None = None
    connect_timeout: float = 5.0
    read_timeout: float = 10.0


@dataclass
class _RetryPolicy:
    attempts: int = 3
    base_delay: float = 0.5
    max_delay: float = 4.0
    retry_status: tuple[int, ...] = (502, 503, 504)


class OPNsenseClient:
    def __init__(
        self,
        host: OPNsenseHost,
        session: requests.Session | None = None,
        retry: _RetryPolicy | None = None,
    ) -> None:
        if not host.url.startswith("https://"):
            raise ValueError("OPNsense API requires HTTPS")
        self.host = host
        self._session = session or requests.Session()
        self._session.auth = HTTPBasicAuth(host.api_key, host.api_secret)
        self._verify: bool | str = host.ca_bundle_path or host.verify_tls
        self._retry = retry or _RetryPolicy()

    # ------------------------------------------------------------------ verbs

    def get(self, path: str, **params: Any) -> dict[str, Any]:
        """GET with retry on transient 5xx + connection errors."""
        return self._request("GET", path, params=params, retry=True)

    def post(self, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        """POST. Never retried — caller owns reconcile."""
        return self._request("POST", path, json=payload or {}, retry=False)

    # --------------------------------------------------------------- internal

    def _url(self, path: str) -> str:
        if not path.startswith("/"):
            path = "/" + path
        return urljoin(self.host.url, path)

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json: dict[str, Any] | None = None,
        retry: bool,
    ) -> dict[str, Any]:
        url = self._url(path)
        last_exc: Exception | None = None
        attempts = self._retry.attempts if retry else 1

        for i in range(attempts):
            try:
                resp = self._session.request(
                    method,
                    url,
                    params=params,
                    json=json,
                    timeout=(self.host.connect_timeout, self.host.read_timeout),
                    verify=self._verify,
                )
            except RequestException as e:
                last_exc = e
                if i == attempts - 1:
                    raise OPNsenseTimeoutError(
                        f"{method} {path} failed after {attempts} attempt(s): {e}"
                    ) from e
                self._sleep_backoff(i)
                continue

            if resp.status_code in (401, 403):
                raise OPNsenseAuthError(
                    f"{method} {path} → {resp.status_code} "
                    f"(check api_key/api_secret + user privileges on host {self.host.name})"
                )

            if resp.status_code in self._retry.retry_status and retry and i < attempts - 1:
                self._sleep_backoff(i)
                continue

            if not resp.ok:
                raise OPNsenseError(
                    f"{method} {path} → HTTP {resp.status_code}: {resp.text[:200]}"
                )

            try:
                return resp.json()
            except ValueError as e:
                raise OPNsenseError(
                    f"{method} {path} → non-JSON response: {resp.text[:200]}"
                ) from e

        # Unreachable, but mypy peace
        raise OPNsenseError(f"{method} {path} exhausted retries: {last_exc}")

    def _sleep_backoff(self, attempt: int) -> None:
        delay = min(self._retry.base_delay * (2 ** attempt), self._retry.max_delay)
        log.debug("retrying after %.2fs (attempt %d)", delay, attempt + 1)
        time.sleep(delay)

    # ------------------------------------------------------------- sugar APIs

    def system_information(self) -> dict[str, Any]:
        """Tiny call used by health checks + smoke tests."""
        return self.get("/api/diagnostics/system/system_information")

    def hasync_get(self) -> dict[str, Any]:
        """Returns the high-availability sync configuration."""
        return self.get("/api/core/hasync/get")
