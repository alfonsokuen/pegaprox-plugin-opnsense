"""Tests for the Prometheus exporter."""
from __future__ import annotations

import json
import pathlib

import responses

from src.client import OPNsenseClient, OPNsenseHost
from src.client.opnsense_client import _RetryPolicy
from src.metrics import render_metrics


FIXTURES = pathlib.Path(__file__).parent.parent / "fixtures" / "live"
HOST = OPNsenseHost(name="lab", url="https://opnsense.test", api_key="k", api_secret="s", verify_tls=False)


def _client() -> OPNsenseClient:
    return OPNsenseClient(HOST, retry=_RetryPolicy(attempts=1, base_delay=0.0, max_delay=0.0))


def _wire_all() -> None:
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
    responses.add(
        responses.GET,
        "https://opnsense.test/api/diagnostics/cpu_usage/getCPUType",
        json=["Intel Xeon (2 cores)"],
        status=200,
    )


@responses.activate
def test_metrics_render_contains_required_metric_names():
    _wire_all()
    body = render_metrics(_client())
    expected = [
        "opnsense_up",
        "opnsense_pf_states_current",
        "opnsense_pf_states_limit",
        "opnsense_memory_used_bytes",
        "opnsense_memory_total_bytes",
        "opnsense_iface_rx_bytes_total",
        "opnsense_iface_tx_bytes_total",
        "opnsense_iface_up",
        "opnsense_gateway_rtt_seconds",
        "opnsense_gateway_loss_ratio",
        "opnsense_gateway_up",
        "opnsense_service_running",
        "opnsense_cert_expiry_seconds",
        "opnsense_vpn_peers_total",
        "opnsense_ha_enabled",
    ]
    for m in expected:
        assert f"# HELP {m} " in body, f"missing HELP for {m}"
        assert f"# TYPE {m} " in body, f"missing TYPE for {m}"


@responses.activate
def test_metrics_includes_host_label_on_every_sample():
    _wire_all()
    body = render_metrics(_client(), host_label="lab")
    sample_lines = [
        ln for ln in body.splitlines()
        if ln and not ln.startswith("#")
    ]
    assert sample_lines, "no metric samples emitted"
    for ln in sample_lines:
        assert 'host="lab"' in ln, f"sample line missing host label: {ln}"


@responses.activate
def test_metrics_iface_lines_have_iface_label():
    _wire_all()
    body = render_metrics(_client())
    rx_lines = [ln for ln in body.splitlines() if ln.startswith("opnsense_iface_rx_bytes_total")]
    assert rx_lines
    for ln in rx_lines:
        assert 'iface="' in ln


@responses.activate
def test_metrics_gateway_loss_is_a_ratio_not_percent():
    _wire_all()
    body = render_metrics(_client())
    # Lab fixture has '~' for delay/loss, so gauge values should be 0.0.
    loss_lines = [
        ln for ln in body.splitlines() if ln.startswith("opnsense_gateway_loss_ratio")
    ]
    assert loss_lines
    for ln in loss_lines:
        # Last whitespace-separated token is the value.
        value = float(ln.rsplit(" ", 1)[-1])
        assert 0.0 <= value <= 1.0, f"loss value out of [0,1]: {ln}"


def test_metrics_renders_up_zero_when_system_call_fails():
    # No mocks → connection error → render_metrics should emit up=0 and stop.
    body = render_metrics(_client())
    assert 'opnsense_up{host="lab"} 0' in body


def test_metrics_text_is_well_formed_text_not_json():
    # No mocks → still parses, no JSON braces leaking through.
    body = render_metrics(_client())
    assert "{" not in body or "{host=" in body  # only label braces allowed
    assert not body.startswith("{")
