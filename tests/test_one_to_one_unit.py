"""Unit tests for OneToOneNatWriter + route."""
from __future__ import annotations

from pathlib import Path

import pytest
import responses

from src.client import OPNsenseClient, OPNsenseHost
from src.client.opnsense_client import _RetryPolicy
from src.routes import (
    build_one_to_one_action_payload,
    build_one_to_one_list_payload,
)
from src.writers import (
    AuditLog,
    OneToOneNatInput,
    OneToOneNatWriter,
)

HOST = OPNsenseHost(name="lab", url="https://opnsense.test", api_key="k", api_secret="s", verify_tls=False)


def _client() -> OPNsenseClient:
    return OPNsenseClient(HOST, retry=_RetryPolicy(attempts=1, base_delay=0.0, max_delay=0.0))


def test_one_to_one_input_payload_shape():
    p = OneToOneNatInput(
        interface="wan", external="190.160.10.50",
        source_net="192.168.1.10", description="x",
    )
    body = p.to_payload()
    assert body == {
        "rule": {
            "enabled": "1",
            "log": "0",
            "sequence": "100",
            "interface": "wan",
            "type": "binat",
            "source_net": "192.168.1.10",
            "source_not": "0",
            "destination_net": "any",
            "destination_not": "0",
            "external": "190.160.10.50",
            "description": "x",
        }
    }


def test_one_to_one_input_validates(tmp_path: Path):
    w = OneToOneNatWriter(_client(), AuditLog(str(tmp_path / "a.jsonl")))
    with pytest.raises(ValueError):
        w.create(OneToOneNatInput(interface="", external="1.2.3.4", source_net="10.0.0.1"))
    with pytest.raises(ValueError):
        w.create(OneToOneNatInput(interface="wan", external="", source_net="10.0.0.1"))
    with pytest.raises(ValueError):
        w.create(OneToOneNatInput(interface="wan", external="1.2.3.4", source_net=""))
    with pytest.raises(ValueError):
        w.create(OneToOneNatInput(interface="wan", external="1.2.3.4", source_net="10.0.0.1", type="rdr"))


@responses.activate
def test_one_to_one_writer_create_and_apply(tmp_path: Path):
    responses.add(
        responses.POST, "https://opnsense.test/api/firewall/one_to_one/addRule",
        json={"result": "saved", "uuid": "o-1"}, status=200,
    )
    responses.add(
        responses.POST, "https://opnsense.test/api/firewall/one_to_one/apply",
        json={"status": "ok"}, status=200,
    )
    w = OneToOneNatWriter(_client(), AuditLog(str(tmp_path / "a.jsonl")))
    out = w.create(OneToOneNatInput(interface="wan", external="1.2.3.4", source_net="10.0.0.1"))
    assert out.ok and out.uuid == "o-1"


@responses.activate
def test_one_to_one_writer_rolls_back_on_apply_fail(tmp_path: Path):
    responses.add(
        responses.POST, "https://opnsense.test/api/firewall/one_to_one/addRule",
        json={"result": "saved", "uuid": "o-2"}, status=200,
    )
    responses.add(
        responses.POST, "https://opnsense.test/api/firewall/one_to_one/apply",
        json={"errorMessage": "boom"}, status=500,
    )
    responses.add(
        responses.POST, "https://opnsense.test/api/firewall/one_to_one/delRule/o-2",
        json={"result": "deleted"}, status=200,
    )
    w = OneToOneNatWriter(_client(), AuditLog(str(tmp_path / "a.jsonl")))
    out = w.create(OneToOneNatInput(interface="wan", external="1.2.3.4", source_net="10.0.0.1"))
    assert not out.ok and "rolled back" in (out.detail or "")


@responses.activate
def test_one_to_one_route_list_payload():
    responses.add(
        responses.GET, "https://opnsense.test/api/firewall/one_to_one/searchRule",
        json={"rows": [{"uuid": "x", "interface": "wan"}], "total": 1}, status=200,
    )
    status, payload = build_one_to_one_list_payload(HOST)
    assert status == 200 and payload["data"]["total"] == 1


def test_one_to_one_route_read_only(tmp_path: Path):
    status, payload = build_one_to_one_action_payload(
        HOST, str(tmp_path), {"action": "create"}, read_only=True
    )
    assert status == 403 and payload["error"] == "read_only"


def test_one_to_one_route_validation(tmp_path: Path):
    status, _ = build_one_to_one_action_payload(
        HOST, str(tmp_path), {"action": "create", "rule": {"interface": "wan"}}
    )
    assert status == 400
