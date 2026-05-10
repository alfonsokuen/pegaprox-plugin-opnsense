"""Unit tests for v0.4.0 collectors (hasync, routes, ARP/NDP, fw log, VPN)."""
from __future__ import annotations

import json
import pathlib

import responses

from src.client import OPNsenseClient, OPNsenseHost
from src.client.opnsense_client import _RetryPolicy
from src.collectors import (
    collect_arp,
    collect_firewall_log,
    collect_hasync,
    collect_ipsec,
    collect_ndp,
    collect_openvpn,
    collect_routes,
    collect_vpn,
    collect_wireguard,
)


FIXTURES = pathlib.Path(__file__).parent.parent / "fixtures" / "live"
HOST = OPNsenseHost(name="lab", url="https://opnsense.test", api_key="k", api_secret="s", verify_tls=False)


def _client() -> OPNsenseClient:
    return OPNsenseClient(HOST, retry=_RetryPolicy(attempts=1, base_delay=0.0, max_delay=0.0))


def _fixture(name: str) -> dict | list:
    return json.loads((FIXTURES / name).read_text())


def _mock(path: str, fixture: str) -> None:
    responses.add(
        responses.GET,
        f"https://opnsense.test{path}",
        json=_fixture(fixture),
        status=200,
    )


# ---- hasync ---------------------------------------------------------------

@responses.activate
def test_hasync_collapses_option_groups():
    _mock("/api/core/hasync/get", "hasync_get.json")
    snap = collect_hasync(_client())
    # Lab has pfsync disabled (peer not configured) — exercise that branch.
    assert isinstance(snap["enabled"], bool)
    assert isinstance(snap["pfsync_interface"], str)
    assert isinstance(snap["pfsync_version"], str)


# ---- routes / ARP / NDP ---------------------------------------------------

@responses.activate
def test_routes_default_present():
    _mock("/api/diagnostics/interface/getRoutes", "getRoutes.json")
    routes = collect_routes(_client())
    # Lab fixture has 13 entries, including a default route.
    assert any(r["destination"] == "default" for r in routes)
    default = next(r for r in routes if r["destination"] == "default")
    assert default["gateway"]
    assert default["netif"]


@responses.activate
def test_arp_returns_neighbors():
    _mock("/api/diagnostics/interface/getArp", "getArp.json")
    arp = collect_arp(_client())
    assert arp
    n = arp[0]
    assert n["family"] == "ipv4"
    assert n["mac"]
    assert n["ip"]


@responses.activate
def test_ndp_returns_ipv6_neighbors():
    _mock("/api/diagnostics/interface/getNdp", "getNdp.json")
    ndp = collect_ndp(_client())
    assert ndp
    assert all(n["family"] == "ipv6" for n in ndp)


# ---- firewall log ---------------------------------------------------------

@responses.activate
def test_firewall_log_projects_slim_shape():
    responses.add(
        responses.GET,
        "https://opnsense.test/api/diagnostics/firewall/log",
        json=_fixture("firewall_log.json"),
        status=200,
    )
    entries = collect_firewall_log(_client(), limit=5)
    assert entries
    e = entries[0]
    # Assert key projection — original payload has 26 fields per entry.
    assert set(e.keys()) == {
        "timestamp", "interface", "action", "direction", "rule_label",
        "src", "dst", "protocol", "ip_version", "length",
    }
    assert e["action"] in ("pass", "block", "rdr", "nat", "binat")


# ---- VPN ------------------------------------------------------------------

@responses.activate
def test_wireguard_with_no_peers():
    _mock("/api/wireguard/general/get", "wireguard_general_get.json")
    _mock("/api/wireguard/service/show", "wireguard_show.json")
    enabled, peers = collect_wireguard(_client())
    assert enabled is False  # lab has WG disabled
    assert peers == []


@responses.activate
def test_wireguard_with_synthetic_peers():
    responses.add(
        responses.GET,
        "https://opnsense.test/api/wireguard/general/get",
        json={"general": {"enabled": "1"}},
        status=200,
    )
    responses.add(
        responses.GET,
        "https://opnsense.test/api/wireguard/service/show",
        json={
            "total": 1,
            "rowCount": 1,
            "current": 1,
            "rows": [
                {
                    "name": "office-laptop",
                    "instance": "wg0",
                    "endpoint": "1.2.3.4:51820",
                    "connected": "1",
                    "enabled": "1",
                }
            ],
        },
        status=200,
    )
    enabled, peers = collect_wireguard(_client())
    assert enabled is True
    assert peers and peers[0]["name"] == "office-laptop"
    assert peers[0]["connected"] is True
    assert peers[0]["remote_address"] == "1.2.3.4:51820"


@responses.activate
def test_ipsec_empty():
    _mock("/api/ipsec/sessions/searchPhase1", "ipsec_searchPhase1.json")
    assert collect_ipsec(_client()) == []


@responses.activate
def test_openvpn_empty():
    _mock("/api/openvpn/service/searchSessions", "openvpn_searchSessions.json")
    assert collect_openvpn(_client()) == []


@responses.activate
def test_vpn_aggregate_snapshot():
    _mock("/api/wireguard/general/get", "wireguard_general_get.json")
    _mock("/api/wireguard/service/show", "wireguard_show.json")
    _mock("/api/ipsec/sessions/searchPhase1", "ipsec_searchPhase1.json")
    _mock("/api/openvpn/service/searchSessions", "openvpn_searchSessions.json")
    snap = collect_vpn(_client())
    assert snap["wireguard_enabled"] is False
    assert snap["wireguard_peers"] == []
    assert snap["ipsec_phase1"] == []
    assert snap["openvpn_sessions"] == []
