"""Unit tests for OPNsenseClusterClient master-resolution + cache."""
from __future__ import annotations

import responses

from src.client import OPNsenseClient, OPNsenseClusterClient, OPNsenseHost
from src.client.opnsense_client import _RetryPolicy

HOST_A = OPNsenseHost(name="A", url="https://a.test", api_key="k", api_secret="s", verify_tls=False)
HOST_B = OPNsenseHost(name="B", url="https://b.test", api_key="k", api_secret="s", verify_tls=False)


def _clients() -> tuple[OPNsenseClient, OPNsenseClient]:
    r = _RetryPolicy(attempts=1, base_delay=0, max_delay=0)
    return OPNsenseClient(HOST_A, retry=r), OPNsenseClient(HOST_B, retry=r)


def _cluster() -> OPNsenseClusterClient:
    a, b = _clients()
    return OPNsenseClusterClient(a, b, name_a="NODOA", name_b="NODOB")


def test_set_carp_cache_short_circuits_http():
    """When the caller pre-populates CARP probes, no HTTP requests should fire."""
    c = _cluster()
    c.set_carp_cache(
        status_a={"role": "master", "enabled": True, "maintenance_mode": False, "vhids": []},
        status_b={"role": "backup", "enabled": True, "maintenance_mode": False, "vhids": []},
    )
    # No `responses.activate` decorator: any HTTP call would raise ConnectionError.
    assert c.master_side() == "a"
    assert c.master_name() == "NODOA"
    assert c.backup_name() == "NODOB"


def test_master_side_when_b_is_master():
    c = _cluster()
    c.set_carp_cache(
        status_a={"role": "backup", "enabled": True, "maintenance_mode": False, "vhids": []},
        status_b={"role": "master", "enabled": True, "maintenance_mode": False, "vhids": []},
    )
    assert c.master_side() == "b"
    assert c.master() is c.b


def test_master_side_defaults_to_a_when_indeterminate():
    """Both master or both backup -> default to A. Caller should consult health()."""
    c = _cluster()
    c.set_carp_cache(
        status_a={"role": "master", "enabled": True, "maintenance_mode": False, "vhids": []},
        status_b={"role": "master", "enabled": True, "maintenance_mode": False, "vhids": []},
    )
    assert c.master_side() == "a"


def test_names_helper():
    c = _cluster()
    assert c.names() == ("NODOA", "NODOB")


@responses.activate
def test_lazy_probes_when_cache_empty():
    """v1.13.1: getCarpStatus is gone; CARP state lives in getVipStatus.carp."""
    responses.add(responses.GET, "https://a.test/api/diagnostics/interface/getVipStatus",
                  json={"rows": [{"vhid": "1", "status": "MASTER", "mode": "carp",
                                  "advbase": "1", "advskew": "0"}],
                        "carp": {"maintenancemode": False, "demotion": "0"}}, status=200)
    responses.add(responses.GET, "https://b.test/api/diagnostics/interface/getVipStatus",
                  json={"rows": [{"vhid": "1", "status": "BACKUP", "mode": "carp",
                                  "advbase": "1", "advskew": "100"}],
                        "carp": {"maintenancemode": False, "demotion": "0"}}, status=200)
    c = _cluster()
    assert c.master_side() == "a"
    assert c.master_name() == "NODOA"


@responses.activate
def test_health_reports_unreachable_node():
    responses.add(responses.GET, "https://a.test/api/core/firmware/info",
                  json={"product_version": "26.1.2"}, status=200)
    # B is down — return a 5xx the client treats as upstream error after retries.
    responses.add(responses.GET, "https://b.test/api/core/firmware/info",
                  json={}, status=503)
    responses.add(responses.GET, "https://b.test/api/core/firmware/info",
                  json={}, status=503)
    responses.add(responses.GET, "https://b.test/api/core/firmware/info",
                  json={}, status=503)
    # When health runs, master resolution may also fire. Pre-populate cache to avoid
    # cluttering the test with CARP fixtures unrelated to the assertion under test.
    c = _cluster()
    c.set_carp_cache(
        status_a={"role": "master", "enabled": True, "maintenance_mode": False, "vhids": []},
        status_b={"role": "unknown", "enabled": False, "maintenance_mode": False, "vhids": []},
    )
    h = c.health()
    assert h["a"]["reachable"] is True
    assert h["b"]["reachable"] is False
    assert h["master"] == "NODOA"
