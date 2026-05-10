"""Unit tests for UnboundWriter / WireguardPeerWriter + routes."""
from __future__ import annotations

from pathlib import Path

import pytest
import responses

from src.client import OPNsenseClient, OPNsenseHost
from src.client.opnsense_client import _RetryPolicy
from src.routes import (
    build_unbound_action_payload,
    build_unbound_domain_action_payload,
    build_unbound_domain_list_payload,
    build_unbound_dot_action_payload,
    build_unbound_dot_list_payload,
    build_unbound_list_payload,
    build_wg_action_payload,
    build_wg_list_payload,
)
from src.writers import (
    AuditLog,
    UnboundDomainInput,
    UnboundDomainWriter,
    UnboundDotInput,
    UnboundDotWriter,
    UnboundHostInput,
    UnboundWriter,
    WireguardPeerInput,
    WireguardPeerWriter,
)

HOST = OPNsenseHost(name="lab", url="https://opnsense.test", api_key="k", api_secret="s", verify_tls=False)


def _client() -> OPNsenseClient:
    return OPNsenseClient(HOST, retry=_RetryPolicy(attempts=1, base_delay=0.0, max_delay=0.0))


# ---------- Unbound ------------------------------------------------------

def test_unbound_input_payload_shape():
    p = UnboundHostInput(hostname="router", domain="lab.local", server="192.168.1.1", description="x")
    body = p.to_payload()
    assert body == {
        "host": {
            "enabled": "1",
            "hostname": "router",
            "domain": "lab.local",
            "rr": "A",
            "server": "192.168.1.1",
            "description": "x",
        }
    }


def test_unbound_input_validates(tmp_path: Path):
    w = UnboundWriter(_client(), AuditLog(str(tmp_path / "a.jsonl")))
    with pytest.raises(ValueError):
        w.create(UnboundHostInput(hostname="", domain="x", server="1.1.1.1"))
    with pytest.raises(ValueError):
        w.create(UnboundHostInput(hostname="x", domain="", server="1.1.1.1"))
    with pytest.raises(ValueError):
        w.create(UnboundHostInput(hostname="x", domain="y", server=""))
    with pytest.raises(ValueError):
        w.create(UnboundHostInput(hostname="x", domain="y", server="1.1.1.1", rr="CNAME"))


@responses.activate
def test_unbound_writer_create_and_apply(tmp_path: Path):
    responses.add(
        responses.POST, "https://opnsense.test/api/unbound/settings/addHostOverride",
        json={"result": "saved", "uuid": "u-1"}, status=200,
    )
    responses.add(
        responses.POST, "https://opnsense.test/api/unbound/service/reconfigure",
        json={"status": "ok"}, status=200,
    )
    w = UnboundWriter(_client(), AuditLog(str(tmp_path / "a.jsonl")))
    out = w.create(UnboundHostInput(hostname="r", domain="d", server="1.2.3.4"))
    assert out.ok and out.uuid == "u-1"


@responses.activate
def test_unbound_writer_rolls_back_on_apply_fail(tmp_path: Path):
    responses.add(
        responses.POST, "https://opnsense.test/api/unbound/settings/addHostOverride",
        json={"result": "saved", "uuid": "u-2"}, status=200,
    )
    responses.add(
        responses.POST, "https://opnsense.test/api/unbound/service/reconfigure",
        json={"errorMessage": "boom"}, status=500,
    )
    responses.add(
        responses.POST, "https://opnsense.test/api/unbound/settings/delHostOverride/u-2",
        json={"result": "deleted"}, status=200,
    )
    w = UnboundWriter(_client(), AuditLog(str(tmp_path / "a.jsonl")))
    out = w.create(UnboundHostInput(hostname="r", domain="d", server="1.2.3.4"))
    assert not out.ok and "rolled back" in (out.detail or "")


@responses.activate
def test_unbound_route_list_payload():
    responses.add(
        responses.GET, "https://opnsense.test/api/unbound/settings/searchHostOverride",
        json={"rows": [{"uuid": "x", "hostname": "h"}], "total": 1}, status=200,
    )
    status, payload = build_unbound_list_payload(HOST)
    assert status == 200 and payload["data"]["total"] == 1


def test_unbound_route_read_only(tmp_path: Path):
    status, payload = build_unbound_action_payload(HOST, str(tmp_path), {"action": "create"}, read_only=True)
    assert status == 403 and payload["error"] == "read_only"


def test_unbound_route_validation(tmp_path: Path):
    status, _ = build_unbound_action_payload(
        HOST, str(tmp_path), {"action": "create", "host": {"hostname": "h"}}
    )
    assert status == 400


# ---------- WireGuard peer ----------------------------------------------

VALID_PUBKEY = "p" * 43 + "="


def test_wgpeer_input_payload_shape():
    p = WireguardPeerInput(name="lap", pubkey=VALID_PUBKEY, tunneladdress="10.99.0.5/32")
    body = p.to_payload()
    assert body["client"]["enabled"] == "1"
    assert body["client"]["name"] == "lap"
    assert body["client"]["pubkey"] == VALID_PUBKEY
    assert body["client"]["keepalive"] == "25"
    assert "psk" not in body["client"]


def test_wgpeer_input_validates(tmp_path: Path):
    w = WireguardPeerWriter(_client(), AuditLog(str(tmp_path / "a.jsonl")))
    with pytest.raises(ValueError):
        w.create(WireguardPeerInput(name="", pubkey=VALID_PUBKEY, tunneladdress="10.0.0.1/32"))
    with pytest.raises(ValueError):
        w.create(WireguardPeerInput(name="x", pubkey="short", tunneladdress="10.0.0.1/32"))
    with pytest.raises(ValueError):
        w.create(WireguardPeerInput(name="x", pubkey=VALID_PUBKEY, tunneladdress="not-cidr"))


@responses.activate
def test_wgpeer_writer_create(tmp_path: Path):
    responses.add(
        responses.POST, "https://opnsense.test/api/wireguard/client/addClient",
        json={"result": "saved", "uuid": "wg-1"}, status=200,
    )
    responses.add(
        responses.POST, "https://opnsense.test/api/wireguard/service/reconfigure",
        json={"status": "ok"}, status=200,
    )
    w = WireguardPeerWriter(_client(), AuditLog(str(tmp_path / "a.jsonl")))
    out = w.create(WireguardPeerInput(name="lap", pubkey=VALID_PUBKEY, tunneladdress="10.99.0.5/32"))
    assert out.ok and out.uuid == "wg-1"


@responses.activate
def test_wgpeer_writer_rolls_back(tmp_path: Path):
    responses.add(
        responses.POST, "https://opnsense.test/api/wireguard/client/addClient",
        json={"result": "saved", "uuid": "wg-2"}, status=200,
    )
    responses.add(
        responses.POST, "https://opnsense.test/api/wireguard/service/reconfigure",
        json={"err": "x"}, status=500,
    )
    responses.add(
        responses.POST, "https://opnsense.test/api/wireguard/client/delClient/wg-2",
        json={"result": "deleted"}, status=200,
    )
    w = WireguardPeerWriter(_client(), AuditLog(str(tmp_path / "a.jsonl")))
    out = w.create(WireguardPeerInput(name="lap", pubkey=VALID_PUBKEY, tunneladdress="10.99.0.5/32"))
    assert not out.ok and "rolled back" in (out.detail or "")


@responses.activate
def test_wg_route_list_payload():
    responses.add(
        responses.GET, "https://opnsense.test/api/wireguard/client/searchClient",
        json={"rows": [{"uuid": "p", "name": "n"}], "total": 1}, status=200,
    )
    status, payload = build_wg_list_payload(HOST)
    assert status == 200 and payload["data"]["total"] == 1


def test_wg_route_read_only(tmp_path: Path):
    status, payload = build_wg_action_payload(HOST, str(tmp_path), {"action": "create"}, read_only=True)
    assert status == 403


def test_wg_route_validation(tmp_path: Path):
    status, _ = build_wg_action_payload(
        HOST, str(tmp_path), {"action": "create", "peer": {"name": "x"}},
    )
    assert status == 400


# ---------- Unbound domain overrides ------------------------------------

def test_unbound_domain_input_payload_shape():
    p = UnboundDomainInput(domain="internal.lab.local", server="192.168.1.1", description="x")
    body = p.to_payload()
    assert body == {
        "dot": {
            "enabled": "1",
            "type": "forward",
            "domain": "internal.lab.local",
            "server": "192.168.1.1",
            "description": "x",
        }
    }


def test_unbound_domain_input_validates(tmp_path: Path):
    w = UnboundDomainWriter(_client(), AuditLog(str(tmp_path / "a.jsonl")))
    with pytest.raises(ValueError):
        w.create(UnboundDomainInput(domain="", server="1.1.1.1"))
    with pytest.raises(ValueError):
        w.create(UnboundDomainInput(domain="bare", server="1.1.1.1"))
    with pytest.raises(ValueError):
        w.create(UnboundDomainInput(domain="x.y", server=""))


@responses.activate
def test_unbound_domain_writer_create_and_apply(tmp_path: Path):
    responses.add(
        responses.POST, "https://opnsense.test/api/unbound/settings/addForward",
        json={"result": "saved", "uuid": "d-1"}, status=200,
    )
    responses.add(
        responses.POST, "https://opnsense.test/api/unbound/service/reconfigure",
        json={"status": "ok"}, status=200,
    )
    w = UnboundDomainWriter(_client(), AuditLog(str(tmp_path / "a.jsonl")))
    out = w.create(UnboundDomainInput(domain="lab.local", server="1.2.3.4"))
    assert out.ok and out.uuid == "d-1"


@responses.activate
def test_unbound_domain_writer_rolls_back_on_apply_fail(tmp_path: Path):
    responses.add(
        responses.POST, "https://opnsense.test/api/unbound/settings/addForward",
        json={"result": "saved", "uuid": "d-2"}, status=200,
    )
    responses.add(
        responses.POST, "https://opnsense.test/api/unbound/service/reconfigure",
        json={"errorMessage": "boom"}, status=500,
    )
    responses.add(
        responses.POST, "https://opnsense.test/api/unbound/settings/delForward/d-2",
        json={"result": "deleted"}, status=200,
    )
    w = UnboundDomainWriter(_client(), AuditLog(str(tmp_path / "a.jsonl")))
    out = w.create(UnboundDomainInput(domain="lab.local", server="1.2.3.4"))
    assert not out.ok and "rolled back" in (out.detail or "")


@responses.activate
def test_unbound_domain_route_list_payload():
    responses.add(
        responses.GET, "https://opnsense.test/api/unbound/settings/searchForward",
        json={"rows": [{"uuid": "x", "domain": "lab.local"}], "total": 1}, status=200,
    )
    status, payload = build_unbound_domain_list_payload(HOST)
    assert status == 200 and payload["data"]["total"] == 1


def test_unbound_domain_route_read_only(tmp_path: Path):
    status, payload = build_unbound_domain_action_payload(
        HOST, str(tmp_path), {"action": "create"}, read_only=True
    )
    assert status == 403 and payload["error"] == "read_only"


def test_unbound_domain_route_validation(tmp_path: Path):
    status, _ = build_unbound_domain_action_payload(
        HOST, str(tmp_path), {"action": "create", "domain": {"domain": "bare"}}
    )
    assert status == 400


# ---------- Unbound DoT entries -----------------------------------------

def test_unbound_dot_input_payload_shape():
    p = UnboundDotInput(domain=".", server="1.1.1.1", verify="cloudflare-dns.com", description="x")
    body = p.to_payload()
    assert body == {
        "dot": {
            "enabled": "1",
            "type": "dot",
            "domain": ".",
            "server": "1.1.1.1",
            "port": "853",
            "verify": "cloudflare-dns.com",
            "forward_tcp_upstream": "0",
            "forward_first": "0",
            "description": "x",
        }
    }


def test_unbound_dot_input_validates(tmp_path: Path):
    w = UnboundDotWriter(_client(), AuditLog(str(tmp_path / "a.jsonl")))
    with pytest.raises(ValueError):
        w.create(UnboundDotInput(domain="", server="1.1.1.1", verify="x.test"))
    with pytest.raises(ValueError):
        w.create(UnboundDotInput(domain=".", server="", verify="x.test"))
    with pytest.raises(ValueError):
        w.create(UnboundDotInput(domain=".", server="1.1.1.1", verify=""))
    with pytest.raises(ValueError):
        w.create(UnboundDotInput(domain=".", server="1.1.1.1", verify="x.test", port="abc"))


@responses.activate
def test_unbound_dot_writer_create_and_apply(tmp_path: Path):
    responses.add(
        responses.POST, "https://opnsense.test/api/unbound/settings/addForward",
        json={"result": "saved", "uuid": "t-1"}, status=200,
    )
    responses.add(
        responses.POST, "https://opnsense.test/api/unbound/service/reconfigure",
        json={"status": "ok"}, status=200,
    )
    w = UnboundDotWriter(_client(), AuditLog(str(tmp_path / "a.jsonl")))
    out = w.create(UnboundDotInput(domain=".", server="1.1.1.1", verify="cloudflare-dns.com"))
    assert out.ok and out.uuid == "t-1"


@responses.activate
def test_unbound_dot_writer_rolls_back_on_apply_fail(tmp_path: Path):
    responses.add(
        responses.POST, "https://opnsense.test/api/unbound/settings/addForward",
        json={"result": "saved", "uuid": "t-2"}, status=200,
    )
    responses.add(
        responses.POST, "https://opnsense.test/api/unbound/service/reconfigure",
        json={"errorMessage": "boom"}, status=500,
    )
    responses.add(
        responses.POST, "https://opnsense.test/api/unbound/settings/delForward/t-2",
        json={"result": "deleted"}, status=200,
    )
    w = UnboundDotWriter(_client(), AuditLog(str(tmp_path / "a.jsonl")))
    out = w.create(UnboundDotInput(domain=".", server="1.1.1.1", verify="x.test"))
    assert not out.ok and "rolled back" in (out.detail or "")


@responses.activate
def test_unbound_dot_route_list_filters_type():
    responses.add(
        responses.GET, "https://opnsense.test/api/unbound/settings/searchForward",
        json={"rows": [
            {"uuid": "a", "type": "dot", "domain": "."},
            {"uuid": "b", "type": "forward", "domain": "lab.local"},
        ], "total": 2}, status=200,
    )
    status, payload = build_unbound_dot_list_payload(HOST)
    assert status == 200 and payload["data"]["total"] == 1
    assert payload["data"]["dots"][0]["uuid"] == "a"


def test_unbound_dot_route_read_only(tmp_path: Path):
    status, payload = build_unbound_dot_action_payload(
        HOST, str(tmp_path), {"action": "create"}, read_only=True
    )
    assert status == 403 and payload["error"] == "read_only"


def test_unbound_dot_route_validation(tmp_path: Path):
    status, _ = build_unbound_dot_action_payload(
        HOST, str(tmp_path), {"action": "create", "dot": {"domain": "."}}
    )
    assert status == 400
