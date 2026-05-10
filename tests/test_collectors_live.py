"""Live smoke for collectors against the OPNsense lab.

Skipped unless OPNSENSE_LAB_URL/KEY/SECRET are set (see test_client_live.py).
"""
from __future__ import annotations

import os

import pytest

from src.client import OPNsenseClient, OPNsenseHost
from src.collectors import (
    collect_certificates,
    collect_gateways,
    collect_interfaces,
    collect_services,
    collect_system,
)

_REQUIRED = ("OPNSENSE_LAB_URL", "OPNSENSE_LAB_KEY", "OPNSENSE_LAB_SECRET")
_missing = [v for v in _REQUIRED if not os.environ.get(v)]

pytestmark = pytest.mark.skipif(
    bool(_missing),
    reason=f"set {', '.join(_REQUIRED)} to run live smoke (missing: {_missing})",
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


def test_system_live(client: OPNsenseClient) -> None:
    snap = collect_system(client)
    assert snap["name"]
    assert snap["versions"]
    assert snap["memory_total_mb"] > 0
    assert snap["pf_states_limit"] > 0


def test_interfaces_live(client: OPNsenseClient) -> None:
    ifaces = collect_interfaces(client)
    assert ifaces, "expected at least one OPNsense interface"
    assert any(i["is_up"] for i in ifaces)


def test_gateways_live(client: OPNsenseClient) -> None:
    # Lab WAN_DHCP gateway present in fixture; tolerate empty list too.
    gws = collect_gateways(client)
    for g in gws:
        assert g["name"]


def test_services_live(client: OPNsenseClient) -> None:
    summary = collect_services(client)
    assert summary["total"] >= 1
    assert summary["running"] + summary["stopped"] == summary["total"]


def test_certificates_live(client: OPNsenseClient) -> None:
    certs = collect_certificates(client)
    # Lab has at least the GUI HTTPS cert
    assert certs
    assert all(c["uuid"] for c in certs)
