"""Aggregated overview endpoint for the plugin UI.

Two shapes:

* Single-host (back-compat, `build_overview_payload(host)`): returns
  `{ok, data: {system, interfaces, gateways, services, vpn, hasync, certs, carp}}`.
  This is what the plugin has shipped since v1.0; existing tabs depend on the
  top-level fields. v1.13.0 only adds the `carp` field (always present, may
  be `{role: "disabled", ...}` when CARP isn't configured).

* Cluster (`build_overview_payload_cluster(host_a, host_b, names)`): runs the
  single-host build on both nodes in parallel and adds a divergence list.
  Shape: `{ok, cluster: true, data: {nodes: {a: {...}, b: {...}}, divergence: [...], master, names}}`.

Collectors run concurrently within a single node (since v1.12.1) and the
two nodes also run in parallel in cluster mode. Floor for cluster overview
is therefore ~max(single-node TTI) instead of 2× sequential.
"""
from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from src.client import (
    OPNsenseAuthError,
    OPNsenseClient,
    OPNsenseClusterClient,
    OPNsenseError,
    OPNsenseHost,
    OPNsenseTimeoutError,
)
from src.collectors import (
    collect_carp_status,
    collect_certificates,
    collect_gateways,
    collect_hasync,
    collect_interfaces,
    collect_services,
    collect_system,
    collect_vpn,
)
from src.divergence import compute_divergence

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
        "carp": collect_carp_status,
    }
    with ThreadPoolExecutor(max_workers=len(tasks), thread_name_prefix="overview") as ex:
        futures = {name: ex.submit(fn, client) for name, fn in tasks.items()}
        results = {name: fut.result() for name, fut in futures.items()}

    certs = results["certs"]
    certs_expiring = [c for c in certs if c["days_to_expiry"] <= CERT_EXPIRY_WARNING_DAYS]

    return {
        "system": results["system"],
        "interfaces": results["interfaces"],
        "gateways": results["gateways"],
        "services": results["services"],
        "vpn": results["vpn"],
        "hasync": results["hasync"],
        "carp": results["carp"],
        "certs": {
            "total": len(certs),
            "expiring_soon_count": len(certs_expiring),
            "expiring_soon": certs_expiring,
        },
    }


def build_overview_payload(host: OPNsenseHost) -> tuple[int, dict[str, Any]]:
    """Wraps build_overview with auth/timeout error handling."""
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


def build_overview_payload_cluster(
    host_a: OPNsenseHost,
    host_b: OPNsenseHost,
    name_a: str = "NODOA",
    name_b: str = "NODOB",
) -> tuple[int, dict[str, Any]]:
    """Run build_overview on both nodes in parallel and emit cluster shape.

    Reports partial success: if one node fails, the other's data still comes
    through with `error` annotated per-node. The cluster-level `ok` is True
    iff at least one node succeeded.
    """
    client_a = OPNsenseClient(host_a)
    client_b = OPNsenseClient(host_b)
    cluster = OPNsenseClusterClient(client_a, client_b, name_a=name_a, name_b=name_b)

    def _safe_build(c: OPNsenseClient) -> dict[str, Any]:
        try:
            return {"ok": True, "snap": build_overview(c)}
        except OPNsenseAuthError as e:
            return {"ok": False, "error": "auth", "detail": str(e)}
        except OPNsenseTimeoutError as e:
            return {"ok": False, "error": "timeout", "detail": str(e)}
        except OPNsenseError as e:
            return {"ok": False, "error": "upstream", "detail": str(e)}

    with ThreadPoolExecutor(max_workers=2, thread_name_prefix="cluster") as ex:
        fa = ex.submit(_safe_build, client_a)
        fb = ex.submit(_safe_build, client_b)
        ra, rb = fa.result(), fb.result()

    if not (ra["ok"] or rb["ok"]):
        return 502, {"ok": False, "error": "upstream", "detail":
                     f"both nodes failed: A={ra.get('detail')} B={rb.get('detail')}"}

    snap_a = ra.get("snap")
    snap_b = rb.get("snap")
    divergence = compute_divergence(snap_a, snap_b) if (snap_a and snap_b) else []

    # Seed the cluster client's CARP cache from already-collected probes so a
    # subsequent master() call doesn't re-hit OPNsense.
    if snap_a:
        cluster.set_carp_cache(snap_a.get("carp"), None)
    if snap_b:
        cluster.set_carp_cache(None, snap_b.get("carp"))

    try:
        master_name = cluster.master_name() if (snap_a and snap_b) else (
            name_a if snap_a else name_b
        )
    except Exception:  # noqa: BLE001 - never let master resolution break the payload
        master_name = name_a

    return 200, {"ok": True, "cluster": True, "data": {
        "nodes": {
            "a": {"name": name_a, **ra} if ra["ok"] else {"name": name_a, **ra, "snap": None},
            "b": {"name": name_b, **rb} if rb["ok"] else {"name": name_b, **rb, "snap": None},
        },
        "divergence": divergence,
        "master": master_name,
        "names": {"a": name_a, "b": name_b},
    }}
