"""Aggregated overview endpoint for the plugin UI.

Calls the collector layer and returns a single JSON payload the dashboard
front-end can render in one render pass. v1.12.1+ runs the seven collectors
concurrently — each ~15 underlying OPNsense API calls serialised was the
dominant TTI cost on the lab (socat + WAN). Each collector is independent
and the OPNsense client is thread-safe (requests.Session under the hood).
"""
from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from src.client import (
    OPNsenseAuthError,
    OPNsenseClient,
    OPNsenseError,
    OPNsenseHost,
    OPNsenseTimeoutError,
)
from src.collectors import (
    collect_certificates,
    collect_gateways,
    collect_hasync,
    collect_interfaces,
    collect_services,
    collect_system,
    collect_vpn,
)

log = logging.getLogger(__name__)

CERT_EXPIRY_WARNING_DAYS = 30


def build_overview(client: OPNsenseClient) -> dict[str, Any]:
    """Single-shot snapshot for the Overview tab. Pure function — pass any client."""
    tasks = {
        "system": collect_system,
        "interfaces": collect_interfaces,
        "gateways": collect_gateways,
        "services": collect_services,
        "vpn": collect_vpn,
        "hasync": collect_hasync,
        "certs": collect_certificates,
    }
    with ThreadPoolExecutor(max_workers=len(tasks), thread_name_prefix="overview") as ex:
        futures = {name: ex.submit(fn, client) for name, fn in tasks.items()}
        results = {name: fut.result() for name, fut in futures.items()}

    system = results["system"]
    interfaces = results["interfaces"]
    gateways = results["gateways"]
    services = results["services"]
    vpn = results["vpn"]
    hasync = results["hasync"]
    certs = results["certs"]

    certs_expiring = [
        c for c in certs
        if c["days_to_expiry"] <= CERT_EXPIRY_WARNING_DAYS
    ]

    return {
        "system": system,
        "interfaces": interfaces,
        "gateways": gateways,
        "services": services,
        "vpn": vpn,
        "hasync": hasync,
        "certs": {
            "total": len(certs),
            "expiring_soon_count": len(certs_expiring),
            "expiring_soon": certs_expiring,
        },
    }


def build_overview_payload(host: OPNsenseHost) -> tuple[int, dict[str, Any]]:
    """Wraps build_overview with auth/timeout error handling.

    Returns (http_status, payload). Used by the Flask route in `register()`.
    """
    client = OPNsenseClient(host)
    try:
        return 200, {"ok": True, "data": build_overview(client)}
    except OPNsenseAuthError as e:
        log.warning("overview auth failed: %s", e)
        return 401, {"ok": False, "error": "auth", "detail": str(e)}
    except OPNsenseTimeoutError as e:
        log.warning("overview timeout: %s", e)
        return 504, {"ok": False, "error": "timeout", "detail": str(e)}
    except OPNsenseError as e:
        log.exception("overview failed")
        return 502, {"ok": False, "error": "upstream", "detail": str(e)}
