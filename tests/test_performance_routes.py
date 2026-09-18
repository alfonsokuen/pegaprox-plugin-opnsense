from threading import Barrier, Lock
from types import SimpleNamespace

import responses

from src.routes import network, vpn
from tests.test_routes_unit import HOST, _mock_all_endpoints
from tests.test_firewall_handlers import config
from tests.test_firewall_management import Firewall, UUID, ALIAS

pytest_plugins = ["tests.test_firewall_handlers"]


def test_wireguard_native_rows_exclude_interfaces_and_use_peer_status():
    from src.collectors.vpn import collect_wireguard
    rows = [{"type": "interface", "status": "up", "name": "wg0"},
            {"type": "peer", "name": "active", "peer-status": "online"},
            {"type": "peer", "name": "old", "peer-status": "stale"},
            {"type": "peer", "name": "off", "peer-status": "offline"},
            {"name": "legacy", "connected": "1"}]
    client = SimpleNamespace(get=lambda path: {"general": {"enabled": "1"}} if path.endswith("/get") else {"rows": rows})
    enabled, peers = collect_wireguard(client)
    assert enabled is True
    assert [p["name"] for p in peers] == ["active", "old", "off", "legacy"]
    assert [p["connected"] for p in peers] == [True, False, False, True]


def test_network_collectors_run_concurrently_with_isolated_sessions(monkeypatch):
    barrier = Barrier(5)
    lock = Lock()
    clients = []

    def factory():
        client = SimpleNamespace(closed=False)
        client.close = lambda: setattr(client, "closed", True)
        with lock:
            clients.append(client)
        return client

    def collect(client):
        barrier.wait(timeout=3)
        assert not client.closed
        return ["observed"]

    for name in ("interfaces", "gateways", "routes", "arp", "ndp"):
        monkeypatch.setattr(network, "collect_" + name, collect)
    result = network.build_network(None, client_factory=factory)
    assert set(result) == {"interfaces", "gateways", "routes", "arp", "ndp"}
    assert len(clients) == 5 and all(c.closed for c in clients)


@responses.activate
def test_vpn_endpoint_only_collects_vpn_not_entire_cluster():
    _mock_all_endpoints()
    code, out = vpn.build_vpn_payload(HOST)
    assert code == 200 and "wireguard_peers" in out["data"]["vpn"]
    assert len(responses.calls) == 4
    assert all(
        any(part in call.request.url for part in ("wireguard", "ipsec", "openvpn"))
        for call in responses.calls
    )


def test_summary_and_detail_handlers_preserve_permission_metadata(plugin, monkeypatch):
    from flask import Flask
    from src.routes import firewall

    node = Firewall("alias")
    node.rows[UUID] = ALIAS
    monkeypatch.setattr(plugin, "_load_config", lambda: config(read_only=True))
    monkeypatch.setattr(firewall, "OPNsenseClient", lambda _: node)
    with Flask(__name__).test_request_context("/?view=summary"):
        response, code = plugin._h_aliases()
    assert code == 200 and response.json["data"]["read_only"] is True
    assert (
        len(node.calls) == 1 and "revision" not in response.json["data"]["aliases"][0]
    )
    with Flask(__name__).test_request_context("/?uuid=" + UUID):
        response, code = plugin._h_aliases()
    assert code == 200 and response.json["data"]["read_only"] is True
    assert response.json["data"]["item"]["revision"] and len(node.calls) == 2


def test_health_distinguishes_read_only_and_permissions(plugin, monkeypatch):
    monkeypatch.setattr(plugin, "_load_config", lambda: config(read_only=True))
    assert plugin._h_health()["write_restriction"] == "read_only"
    monkeypatch.setattr(plugin, "_load_config", lambda: config(read_only=False))
    monkeypatch.setattr(plugin, "_firewall_can_write", lambda: False)
    assert plugin._h_health()["write_restriction"] == "permission"
    assert plugin._h_health()["can_write"] is False
