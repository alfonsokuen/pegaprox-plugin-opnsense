"""Certificate collector — surfaces expiry-relevant fields.

Skips PEM payloads (`crt`, `prv`, `csr`) on purpose — collectors don't need
material, only metadata. Writers that need the PEM call the API directly.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import TypedDict

from src.client import OPNsenseClient


class CertSummary(TypedDict):
    uuid: str
    name: str
    description: str
    commonname: str
    valid_from: str
    valid_to: str
    days_to_expiry: int      # negative if already expired
    in_use: bool
    is_user: bool
    cert_type: str           # raw value (e.g. "server")
    digest: str              # raw value (e.g. "sha256")


def _parse_days_to(valid_to: str) -> int:
    """OPNsense returns dates as 'May  9 12:34:56 2027 GMT' (UTC). Coerce."""
    if not valid_to:
        return 0
    try:
        dt = datetime.strptime(valid_to.strip(), "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        # Tolerate inputs without explicit TZ
        try:
            dt = datetime.strptime(valid_to.strip()[:24], "%b %d %H:%M:%S %Y").replace(
                tzinfo=timezone.utc
            )
        except ValueError:
            return 0
    delta = dt - datetime.now(timezone.utc)
    return int(delta.total_seconds() // 86400)


def _bool_from(value: object) -> bool:
    try:
        return bool(int(str(value).strip()))
    except (ValueError, AttributeError):
        # OPNsense sometimes returns "" → False
        return bool(value) if isinstance(value, bool) else False


def collect_certificates(client: OPNsenseClient) -> list[CertSummary]:
    payload = client.get("/api/trust/cert/search")
    rows = payload.get("rows", []) if isinstance(payload, dict) else []
    out: list[CertSummary] = []
    for r in rows:
        valid_to = str(r.get("valid_to") or "")
        out.append(
            CertSummary(
                uuid=str(r.get("uuid", "")),
                name=str(r.get("name", "")),
                description=str(r.get("descr", "")),
                commonname=str(r.get("commonname", "")),
                valid_from=str(r.get("valid_from", "")),
                valid_to=valid_to,
                days_to_expiry=_parse_days_to(valid_to),
                in_use=_bool_from(r.get("in_use")),
                is_user=_bool_from(r.get("is_user")),
                cert_type=str(r.get("cert_type", "")),
                digest=str(r.get("digest", "")),
            )
        )
    return out
