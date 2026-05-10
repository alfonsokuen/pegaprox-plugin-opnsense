"""Unit tests for DhcpReservationWriter + route."""
from __future__ import annotations

from pathlib import Path

import pytest
import responses

from src.client import OPNsenseClient, OPNsenseHost
from src.client.opnsense_client import _RetryPolicy
from src.routes import build_dhcp_action_payload, build_dhcp_list_payload
from src.writers import AuditLog, DhcpReservationInput, DhcpReservationWriter

HOST = OPNsenseHost(name="lab", url="https://opnsense.test", api_key="k", api_secret="s", verify_tls=False)


def _client() -> OPNsenseClient:
    return OPNsenseClient(HOST, retry=_RetryPolicy(attempts=1, base_delay=0.0, max_delay=0.0))


def test_dhcp_input_payload_shape():
    p = DhcpReservationInput(
        subnet="abc-uuid", ip_address="192.168.1.50",
        hw_address="AA:BB:CC:DD:EE:FF", hostname="qa", description="x",
    )
    body = p.to_payload()
    assert body == {
        "reservation": {
            "subnet": "abc-uuid",
            "ip_address": "192.168.1.50",
            "hw_address": "AA:BB:CC:DD:EE:FF",
            "hostname": "qa",
            "description": "x",
        }
    }


def test_dhcp_input_validates(tmp_path: Path):
    w = DhcpReservationWriter(_client(), AuditLog(str(tmp_path / "a.jsonl")))
    with pytest.raises(ValueError):
        w.create(DhcpReservationInput(subnet="", ip_address="1.2.3.4", hw_address="AA:BB:CC:DD:EE:FF", hostname="h"))
    with pytest.raises(ValueError):
        w.create(DhcpReservationInput(subnet="u", ip_address="not-ip", hw_address="AA:BB:CC:DD:EE:FF", hostname="h"))
    with pytest.raises(ValueError):
        w.create(DhcpReservationInput(subnet="u", ip_address="1.2.3.4", hw_address="not-mac", hostname="h"))
    with pytest.raises(ValueError):
        w.create(DhcpReservationInput(subnet="u", ip_address="1.2.3.4", hw_address="AA:BB:CC:DD:EE:FF", hostname=""))


@responses.activate
def test_dhcp_writer_create_and_apply(tmp_path: Path):
    responses.add(
        responses.POST, "https://opnsense.test/api/kea/dhcpv4/addReservation",
        json={"result": "saved", "uuid": "d-1"}, status=200,
    )
    responses.add(
        responses.POST, "https://opnsense.test/api/kea/service/reconfigure",
        json={"status": "ok"}, status=200,
    )
    w = DhcpReservationWriter(_client(), AuditLog(str(tmp_path / "a.jsonl")))
    out = w.create(DhcpReservationInput(
        subnet="abc", ip_address="192.168.1.50",
        hw_address="AA:BB:CC:DD:EE:FF", hostname="qa",
    ))
    assert out.ok and out.uuid == "d-1"


@responses.activate
def test_dhcp_writer_rolls_back_on_apply_fail(tmp_path: Path):
    responses.add(
        responses.POST, "https://opnsense.test/api/kea/dhcpv4/addReservation",
        json={"result": "saved", "uuid": "d-2"}, status=200,
    )
    responses.add(
        responses.POST, "https://opnsense.test/api/kea/service/reconfigure",
        json={"errorMessage": "boom"}, status=500,
    )
    responses.add(
        responses.POST, "https://opnsense.test/api/kea/dhcpv4/delReservation/d-2",
        json={"result": "deleted"}, status=200,
    )
    w = DhcpReservationWriter(_client(), AuditLog(str(tmp_path / "a.jsonl")))
    out = w.create(DhcpReservationInput(
        subnet="abc", ip_address="192.168.1.50",
        hw_address="AA:BB:CC:DD:EE:FF", hostname="qa",
    ))
    assert not out.ok and "rolled back" in (out.detail or "")


@responses.activate
def test_dhcp_route_list_payload():
    responses.add(
        responses.GET, "https://opnsense.test/api/kea/dhcpv4/searchReservation",
        json={"rows": [{"uuid": "x", "hostname": "h"}], "total": 1}, status=200,
    )
    responses.add(
        responses.GET, "https://opnsense.test/api/kea/dhcpv4/searchSubnet",
        json={"rows": [{"uuid": "s1", "subnet": "192.168.1.0/24"}], "total": 1}, status=200,
    )
    status, payload = build_dhcp_list_payload(HOST)
    assert status == 200
    assert payload["data"]["total"] == 1
    assert len(payload["data"]["subnets"]) == 1


def test_dhcp_route_read_only(tmp_path: Path):
    status, payload = build_dhcp_action_payload(HOST, str(tmp_path), {"action": "create"}, read_only=True)
    assert status == 403 and payload["error"] == "read_only"


def test_dhcp_route_validation(tmp_path: Path):
    status, _ = build_dhcp_action_payload(
        HOST, str(tmp_path), {"action": "create", "reservation": {"hostname": "h"}}
    )
    assert status == 400
