"""Unit tests for DhcpSubnetWriter + route."""
from __future__ import annotations

from pathlib import Path

import pytest
import responses

from src.client import OPNsenseClient, OPNsenseHost
from src.client.opnsense_client import _RetryPolicy
from src.routes import build_dhcp_subnet_action_payload, build_dhcp_subnet_list_payload
from src.writers import AuditLog, DhcpSubnetInput, DhcpSubnetWriter

HOST = OPNsenseHost(name="lab", url="https://opnsense.test", api_key="k", api_secret="s", verify_tls=False)


def _client() -> OPNsenseClient:
    return OPNsenseClient(HOST, retry=_RetryPolicy(attempts=1, base_delay=0.0, max_delay=0.0))


def test_dhcp_subnet_input_payload_shape():
    p = DhcpSubnetInput(
        subnet="192.168.1.0/24",
        description="qa",
        pools="192.168.1.100-192.168.1.200",
        next_server="192.168.1.1",
    )
    body = p.to_payload()
    assert body == {
        "subnet4": {
            "subnet": "192.168.1.0/24",
            "description": "qa",
            "pools": "192.168.1.100-192.168.1.200",
            "next_server": "192.168.1.1",
            "match-client-id": "1",
        }
    }


def test_dhcp_subnet_input_validates_cidr(tmp_path: Path):
    w = DhcpSubnetWriter(_client(), AuditLog(str(tmp_path / "a.jsonl")))
    with pytest.raises(ValueError):
        w.create(DhcpSubnetInput(subnet=""))
    with pytest.raises(ValueError):
        w.create(DhcpSubnetInput(subnet="not-cidr"))
    with pytest.raises(ValueError):
        w.create(DhcpSubnetInput(subnet="192.168.1.0"))  # missing /N
    with pytest.raises(ValueError):
        w.create(DhcpSubnetInput(subnet="not.an.ip/24"))


def test_dhcp_subnet_match_client_id_serializes():
    a = DhcpSubnetInput(subnet="10.0.0.0/8", match_client_id=True).to_payload()
    b = DhcpSubnetInput(subnet="10.0.0.0/8", match_client_id=False).to_payload()
    assert a["subnet4"]["match-client-id"] == "1"
    assert b["subnet4"]["match-client-id"] == "0"


@responses.activate
def test_dhcp_subnet_writer_create_and_apply(tmp_path: Path):
    responses.add(
        responses.POST, "https://opnsense.test/api/kea/dhcpv4/addSubnet",
        json={"result": "saved", "uuid": "s-1"}, status=200,
    )
    responses.add(
        responses.POST, "https://opnsense.test/api/kea/service/reconfigure",
        json={"status": "ok"}, status=200,
    )
    w = DhcpSubnetWriter(_client(), AuditLog(str(tmp_path / "a.jsonl")))
    out = w.create(DhcpSubnetInput(subnet="10.99.0.0/24", description="qa"))
    assert out.ok and out.uuid == "s-1"


@responses.activate
def test_dhcp_subnet_writer_rolls_back_on_apply_fail(tmp_path: Path):
    responses.add(
        responses.POST, "https://opnsense.test/api/kea/dhcpv4/addSubnet",
        json={"result": "saved", "uuid": "s-2"}, status=200,
    )
    responses.add(
        responses.POST, "https://opnsense.test/api/kea/service/reconfigure",
        json={"errorMessage": "boom"}, status=500,
    )
    responses.add(
        responses.POST, "https://opnsense.test/api/kea/dhcpv4/delSubnet/s-2",
        json={"result": "deleted"}, status=200,
    )
    w = DhcpSubnetWriter(_client(), AuditLog(str(tmp_path / "a.jsonl")))
    out = w.create(DhcpSubnetInput(subnet="10.99.0.0/24"))
    assert not out.ok and "rolled back" in (out.detail or "")


@responses.activate
def test_dhcp_subnet_route_list_payload():
    responses.add(
        responses.GET, "https://opnsense.test/api/kea/dhcpv4/searchSubnet",
        json={"rows": [{"uuid": "x", "subnet": "10.0.0.0/24"}], "total": 1}, status=200,
    )
    status, payload = build_dhcp_subnet_list_payload(HOST)
    assert status == 200 and payload["data"]["total"] == 1


def test_dhcp_subnet_route_read_only(tmp_path: Path):
    status, payload = build_dhcp_subnet_action_payload(
        HOST, str(tmp_path), {"action": "create"}, read_only=True
    )
    assert status == 403 and payload["error"] == "read_only"


def test_dhcp_subnet_route_validation(tmp_path: Path):
    status, _ = build_dhcp_subnet_action_payload(
        HOST, str(tmp_path), {"action": "create", "subnet": {"subnet": "garbage"}}
    )
    assert status == 400
