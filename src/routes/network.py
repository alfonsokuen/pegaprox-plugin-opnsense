"""Network detail endpoint — interfaces + gateways + routes + neighbors.

Used by the Network tab. Heavier than overview (ARP/NDP can be hundreds of
rows) so it's its own route to keep the overview tick fast.
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
    collect_arp,
    collect_gateways,
    collect_interfaces,
    collect_ndp,
    collect_routes,
)

log = logging.getLogger(__name__)


def build_network(client: OPNsenseClient | None, *, client_factory=None) -> dict[str, Any]:
    tasks = {"interfaces": collect_interfaces, "gateways": collect_gateways,
             "routes": collect_routes, "arp": collect_arp, "ndp": collect_ndp}
    if client_factory is None:
        return {name: collect(client) for name, collect in tasks.items()}
    # Independent GET collectors, bounded to five sessions. No shared cookie jar.
    def collect_one(collect):
        isolated = client_factory()
        try:
            return collect(isolated)
        finally:
            isolated.close()
    with ThreadPoolExecutor(max_workers=len(tasks), thread_name_prefix="network") as pool:
        futures = {name: pool.submit(collect_one, collect) for name, collect in tasks.items()}
        return {name: future.result() for name, future in futures.items()}


def build_network_payload(host: OPNsenseHost) -> tuple[int, dict[str, Any]]:
    try:
        return 200, {"ok": True, "data": build_network(None, client_factory=lambda: OPNsenseClient(host))}
    except OPNsenseAuthError as e:
        return 401, {"ok": False, "error": "auth", "detail": str(e)}
    except OPNsenseTimeoutError as e:
        return 504, {"ok": False, "error": "timeout", "detail": str(e)}
    except OPNsenseError as e:
        log.exception("network failed")
        return 502, {"ok": False, "error": "upstream", "detail": str(e)}
