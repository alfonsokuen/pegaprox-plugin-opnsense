"""Tests for route-layer aggregation, mocked end-to-end."""
from __future__ import annotations

import json
import pathlib

import pytest
import responses

from src.client import OPNsenseClient, OPNsenseHost
from src.client.opnsense_client import _RetryPolicy
from src.routes import (
    build_logs_payload,
    build_network,
    build_network_payload,
    build_overview,
    build_overview_payload,
)
from src.routes.logs import _clamp_limit


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
    # CARP (v1.13.0). Lab is single-host, no CARP — mock the disabled shape.
    responses.add(
        responses.GET,
        "https://opnsense.test/api/diagnostics/interface/getCarpStatus",
        json={"carp_enabled": "0", "maintenance_mode": "0"},
        status=200,
    )
    responses.add(
        responses.GET,
        "https://opnsense.test/api/diagnostics/interface/getVipStatus",
        json={"rows": []},
        status=200,
    )


@responses.activate
def test_overview_aggregates_all_subsystems():
    _mock_all_endpoints()
    out = build_overview(_client())

    assert set(out.keys()) == {
        "system", "interfaces", "gateways", "services", "vpn", "hasync", "certs", "carp",
    }
    assert out["carp"]["role"] == "disabled"  # lab fixture has CARP off
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


# ---------- /network ----------

def _mock_network_endpoints() -> None:
    pairs = [
        ("/api/diagnostics/interface/getInterfaceConfig", "interface_config.json"),
        ("/api/diagnostics/interface/getInterfaceStatistics", "interface_statistics.json"),
        ("/api/routes/gateway/status", "gateway_status.json"),
        ("/api/diagnostics/interface/getRoutes", "getRoutes.json"),
        ("/api/diagnostics/interface/getArp", "getArp.json"),
        ("/api/diagnostics/interface/getNdp", "getNdp.json"),
    ]
    for path, fixture in pairs:
        responses.add(
            responses.GET,
            f"https://opnsense.test{path}",
            json=json.loads((FIXTURES / fixture).read_text()),
            status=200,
        )


@responses.activate
def test_network_aggregates_keys():
    _mock_network_endpoints()
    out = build_network(_client())
    assert set(out.keys()) == {"interfaces", "gateways", "routes", "arp", "ndp"}
    assert isinstance(out["routes"], list)
    assert isinstance(out["arp"], list)
    assert isinstance(out["ndp"], list)


@responses.activate
def test_network_payload_ok_envelope():
    _mock_network_endpoints()
    status, payload = build_network_payload(HOST)
    assert status == 200
    assert payload["ok"] is True
    assert "interfaces" in payload["data"]


@responses.activate
def test_network_payload_auth_failure():
    responses.add(
        responses.GET,
        "https://opnsense.test/api/diagnostics/interface/getInterfaceConfig",
        json={"message": "no"},
        status=401,
    )
    status, payload = build_network_payload(HOST)
    assert status == 401
    assert payload["error"] == "auth"


# ---------- /logs ----------

def test_logs_clamp_limit_defaults():
    assert _clamp_limit(None) == 100
    assert _clamp_limit("abc") == 100
    assert _clamp_limit(0) == 100
    assert _clamp_limit(-50) == 100


def test_logs_clamp_limit_caps_at_max():
    assert _clamp_limit(50) == 50
    assert _clamp_limit(500) == 500
    assert _clamp_limit(10000) == 500
    assert _clamp_limit("250") == 250


@responses.activate
def test_logs_payload_returns_entries():
    responses.add(
        responses.GET,
        "https://opnsense.test/api/diagnostics/firewall/log?limit=100",
        json=json.loads((FIXTURES / "firewall_log.json").read_text()),
        status=200,
        match_querystring=True,
    )
    status, payload = build_logs_payload(HOST, limit=100)
    assert status == 200
    assert payload["ok"] is True
    assert payload["data"]["limit"] == 100
    assert isinstance(payload["data"]["entries"], list)


@responses.activate
def test_logs_payload_auth_failure():
    responses.add(
        responses.GET,
        "https://opnsense.test/api/diagnostics/firewall/log?limit=100",
        json={"message": "no"},
        status=401,
        match_querystring=True,
    )
    status, payload = build_logs_payload(HOST, limit=100)
    assert status == 401
    assert payload["error"] == "auth"
