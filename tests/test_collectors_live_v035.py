"""Live smoke for the v0.4.0 collectors against the lab."""
from __future__ import annotations

import os

import pytest

from src.client import OPNsenseClient, OPNsenseHost
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

_REQUIRED = ("OPNSENSE_LAB_URL", "OPNSENSE_LAB_KEY", "OPNSENSE_LAB_SECRET")
_missing = [v for v in _REQUIRED if not os.environ.get(v)]

pytestmark = pytest.mark.skipif(
    bool(_missing), reason=f"set {', '.join(_REQUIRED)} (missing: {_missing})"
)


@pytest.fixture
def client() -> OPNsenseClient:
    return OPNsenseClient(
        OPNsenseHost(
            name="lab",
            url=os.environ["OPNSENSE_LAB_URL"],
            api_key=os.environ["OPNSENSE_LAB_KEY"],
            api_secret=os.environ["OPNSENSE_LAB_SECRET"],
            verify_tls=False,
        )
    )


def test_hasync_live(client: OPNsenseClient) -> None:
    snap = collect_hasync(client)
    # Lab has HA disabled; just confirm shape.
    assert isinstance(snap["enabled"], bool)


def test_routes_live(client: OPNsenseClient) -> None:
    routes = collect_routes(client)
    assert routes
    assert any(r["destination"] == "default" for r in routes)


def test_arp_live(client: OPNsenseClient) -> None:
    arp = collect_arp(client)
    # ARP may be empty initially; tolerate. Just shape-check on any entries.
    for n in arp:
        assert n["family"] == "ipv4"


def test_ndp_live(client: OPNsenseClient) -> None:
    ndp = collect_ndp(client)
    for n in ndp:
        assert n["family"] == "ipv6"


def test_firewall_log_live(client: OPNsenseClient) -> None:
    log = collect_firewall_log(client, limit=10)
    # Quiet lab still drops/blocks scan traffic on WAN — almost always non-empty.
    for e in log:
        assert e["action"] in ("pass", "block", "rdr", "nat", "binat")


def test_wireguard_live(client: OPNsenseClient) -> None:
    enabled, peers = collect_wireguard(client)
    assert isinstance(enabled, bool)
    assert isinstance(peers, list)


def test_ipsec_live(client: OPNsenseClient) -> None:
    assert isinstance(collect_ipsec(client), list)


def test_openvpn_live(client: OPNsenseClient) -> None:
    assert isinstance(collect_openvpn(client), list)


def test_vpn_aggregate_live(client: OPNsenseClient) -> None:
    snap = collect_vpn(client)
    assert "wireguard_enabled" in snap
    assert isinstance(snap["wireguard_peers"], list)
