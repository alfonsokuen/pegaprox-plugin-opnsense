"""Tests for route-layer aggregation, mocked end-to-end."""
from __future__ import annotations

import json
import pathlib

import pytest
import responses

from src.client import OPNsenseClient, OPNsenseHost
from src.client.opnsense_client import _RetryPolicy
from src.routes import build_overview, build_overview_payload


FIXTURES = pathlib.Path(__file__).parent.parent / "fixtures" / "live"
HOST = OPNsenseHost(name="lab", url="https://opnsense.test", api_key="k", api_secret="s", verify_tls=False)


def _client() -> OPNsenseClient:
    return OPNsenseClient(HOST, retry=_RetryPolicy(attempts=1, base_delay=0.0, max_delay=0.0))


def _mock_all_endpoints() -> None:
    """Wire every collector endpoint to its captured live fixture."""
    pairs = [
        ("/api/diagnostics/system/system_information", "system_information.json"),
        ("/api/diagnostics/system/systemResources", "systemResources.json"),
        ("/api/diagnostics/system/systemTime", "systemTime.json"),
        ("/api/diagnostics/firewall/pf_states", "pf_states.json"),
        ("/api/diagnostics/interface/getInterfaceConfig", "interface_config.json"),
        ("/api/diagnostics/interface/getInterfaceStatistics", "interface_statistics.json"),
        ("/api/routes/gateway/status", "gateway_status.json"),
        ("/api/core/service/search", "service_search.json"),
        ("/api/wireguard/general/get", "wireguard_general_get.json"),
        ("/api/wireguard/service/show", "wireguard_show.json"),
        ("/api/ipsec/sessions/searchPhase1", "ipsec_searchPhase1.json"),
        ("/api/openvpn/service/searchSessions", "openvpn_searchSessions.json"),
        ("/api/core/hasync/get", "hasync_get.json"),
        ("/api/trust/cert/search", "cert_search.json"),
    ]
    for path, fixture in pairs:
        responses.add(
            responses.GET,
            f"https://opnsense.test{path}",
            json=json.loads((FIXTURES / fixture).read_text()),
            status=200,
        )
    # Optional — collector tolerates failure but we wire it anyway.
    responses.add(
        responses.GET,
        "https://opnsense.test/api/diagnostics/cpu_usage/getCPUType",
        json=["Intel(R) Xeon(R) Gold 6138 CPU @ 2.00GHz (2 cores, 2 threads)"],
        status=200,
    )


@responses.activate
def test_overview_aggregates_all_subsystems():
    _mock_all_endpoints()
    out = build_overview(_client())

    assert set(out.keys()) == {
        "system", "interfaces", "gateways", "services", "vpn", "hasync", "certs",
    }
    assert out["system"]["name"] == "OPNsense.internal"
    assert out["interfaces"], "expected at least one iface"
    assert "items" in out["services"]
    assert "wireguard_enabled" in out["vpn"]
    assert "expiring_soon" in out["certs"]
    assert out["certs"]["total"] >= 1


@responses.activate
def test_overview_certs_expiring_soon_filter():
    _mock_all_endpoints()
    out = build_overview(_client())
    # Lab's self-signed GUI cert lifetime is 825 days, so it should NOT be
    # in the expiring-soon bucket. Sanity-check the filter still applies.
    assert all(
        c["days_to_expiry"] <= 30 for c in out["certs"]["expiring_soon"]
    )


@responses.activate
def test_overview_payload_ok_envelope():
    _mock_all_endpoints()
    status, payload = build_overview_payload(HOST)
    assert status == 200
    assert payload["ok"] is True
    assert payload["data"]["system"]["name"] == "OPNsense.internal"


@responses.activate
def test_overview_payload_auth_failure():
    responses.add(
        responses.GET,
        "https://opnsense.test/api/diagnostics/system/system_information",
        json={"message": "no"},
        status=401,
    )
    status, payload = build_overview_payload(HOST)
    assert status == 401
    assert payload["ok"] is False
    assert payload["error"] == "auth"


@responses.activate
def test_overview_payload_upstream_failure():
    # Server returns 500 — exhausts retries and surfaces as 502 from our route.
    for _ in range(3):
        responses.add(
            responses.GET,
            "https://opnsense.test/api/diagnostics/system/system_information",
            json={"message": "boom"},
            status=500,
        )
    status, payload = build_overview_payload(HOST)
    assert status == 502
    assert payload["ok"] is False
    assert payload["error"] == "upstream"


@pytest.mark.parametrize("missing_key", [
    "system", "interfaces", "gateways", "services", "vpn", "hasync", "certs",
])
@responses.activate
def test_overview_payload_shape_keys_present(missing_key: str):
    _mock_all_endpoints()
    out = build_overview(_client())
    assert missing_key in out
