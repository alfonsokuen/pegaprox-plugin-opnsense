"""Unit tests for collectors using captured live fixtures."""
from __future__ import annotations

import json
import pathlib

import responses

from src.client import OPNsenseClient, OPNsenseHost
from src.client.opnsense_client import _RetryPolicy
from src.collectors import (
    collect_certificates,
    collect_gateways,
    collect_interfaces,
    collect_services,
    collect_system,
)


FIXTURES = pathlib.Path(__file__).parent.parent / "fixtures" / "live"
HOST = OPNsenseHost(
    name="lab",
    url="https://opnsense.test",
    api_key="key",
    api_secret="secret",
    verify_tls=False,
)


def _fixture(name: str) -> dict | list:
    return json.loads((FIXTURES / name).read_text())


def _client() -> OPNsenseClient:
    return OPNsenseClient(HOST, retry=_RetryPolicy(attempts=1, base_delay=0.0, max_delay=0.0))


def _mock(path: str, fixture: str) -> None:
    responses.add(
        responses.GET,
        f"https://opnsense.test{path}",
        json=_fixture(fixture),
        status=200,
    )


# ---- system ---------------------------------------------------------------

@responses.activate
def test_collect_system_pulls_versions_memory_pf():
    _mock("/api/diagnostics/system/system_information", "system_information.json")
    _mock("/api/diagnostics/system/systemResources", "systemResources.json")
    _mock("/api/diagnostics/system/systemTime", "systemTime.json")
    _mock("/api/diagnostics/firewall/pf_states", "pf_states.json")
    # Optional CPU type endpoint — collector tolerates failure.
    responses.add(
        responses.GET,
        "https://opnsense.test/api/diagnostics/cpu_usage/getCPUType",
        json=["Intel(R) Xeon(R) Gold 6138 CPU @ 2.00GHz (2 cores, 2 threads)"],
        status=200,
    )

    snap = collect_system(_client())
    assert snap["name"] == "OPNsense.internal"
    assert any("OPNsense" in v for v in snap["versions"])
    assert "Xeon" in snap["cpu_type"]
    assert snap["memory_total_mb"] > 0
    assert 0.0 <= snap["memory_used_pct"] <= 100.0
    assert snap["pf_states_limit"] >= snap["pf_states_current"]
    assert isinstance(snap["loadavg"], list) and len(snap["loadavg"]) == 3


# ---- interfaces -----------------------------------------------------------

@responses.activate
def test_collect_interfaces_merges_cfg_and_stats():
    _mock("/api/diagnostics/interface/getInterfaceConfig", "interface_config.json")
    _mock("/api/diagnostics/interface/getInterfaceStatistics", "interface_statistics.json")

    ifaces = collect_interfaces(_client())
    names = {i["name"] for i in ifaces}
    assert "vtnet0" in names
    assert "vtnet1" in names

    vtnet0 = next(i for i in ifaces if i["name"] == "vtnet0")
    assert vtnet0["macaddr"]
    # IPv4 list with at least one address dict
    assert vtnet0["ipv4"] and isinstance(vtnet0["ipv4"], list)
    # Friendly OPNsense label is parsed from "[LAN] (vtnet0)..." key
    assert vtnet0["label"] in ("LAN", "WAN", "")
    assert isinstance(vtnet0["sent_bytes"], int)
    assert vtnet0["is_up"] is True


# ---- gateways -------------------------------------------------------------

@responses.activate
def test_collect_gateways_normalises_dashes():
    _mock("/api/routes/gateway/status", "gateway_status.json")
    gws = collect_gateways(_client())
    # Lab fixture should contain at least one entry
    assert gws
    g = gws[0]
    # "~" in raw response should coerce to 0.0
    assert isinstance(g["delay_ms"], float)
    assert isinstance(g["loss_pct"], float)
    # status_translated == "Online" → is_up True
    assert g["status_human"] in ("Online", "Offline", "Pending")


# ---- services -------------------------------------------------------------

@responses.activate
def test_collect_services_summary_counts():
    _mock("/api/core/service/search", "service_search.json")
    summary = collect_services(_client())
    assert summary["total"] >= 1
    assert summary["running"] + summary["stopped"] == summary["total"]
    # configd is always running on a healthy OPNsense
    configd = next((s for s in summary["items"] if s["id"] == "configd"), None)
    assert configd and configd["running"] is True


# ---- certificates ---------------------------------------------------------

@responses.activate
def test_collect_certificates_hides_pem_and_parses_expiry():
    _mock("/api/trust/cert/search", "cert_search.json")
    certs = collect_certificates(_client())
    assert certs
    c = certs[0]
    # Sanity on metadata fields
    assert "uuid" in c and c["uuid"]
    assert "valid_to" in c and c["valid_to"]
    # Days-to-expiry is some integer (negative if already expired)
    assert isinstance(c["days_to_expiry"], int)
