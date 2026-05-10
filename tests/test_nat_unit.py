"""Unit tests for the source NAT writer + route."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
import responses

from src.client import OPNsenseClient, OPNsenseHost
from src.client.opnsense_client import _RetryPolicy
from src.routes import build_nat_action_payload, build_nat_list_payload
from src.writers import AuditLog, NatInput, NatWriter

HOST = OPNsenseHost(name="lab", url="https://opnsense.test", api_key="k", api_secret="s", verify_tls=False)


def _client() -> OPNsenseClient:
    return OPNsenseClient(HOST, retry=_RetryPolicy(attempts=1, base_delay=0.0, max_delay=0.0))


# ---- NatInput validation -----------------------------------------------

def test_nat_input_payload_shape():
    p = NatInput(interface="wan", target="1.2.3.4", source_net="192.168.1.0/24", description="test")
    body = p.to_payload()
    assert body == {
        "rule": {
            "disabled": "0",
            "interface": "wan",
            "ipprotocol": "inet",
            "protocol": "any",
            "source_net": "192.168.1.0/24",
            "destination_net": "any",
            "target": "1.2.3.4",
            "description": "test",
        }
    }


def test_nat_input_disabled_when_not_enabled():
    p = NatInput(interface="wan", target="1.2.3.4", enabled=False)
    assert p.to_payload()["rule"]["disabled"] == "1"


# ---- NatWriter.create + delete -----------------------------------------

@responses.activate
def test_nat_writer_create_happy_path(tmp_path: Path):
    responses.add(
        responses.POST, "https://opnsense.test/api/firewall/source_nat/addRule",
        json={"result": "saved", "uuid": "u-1"}, status=200,
    )
    responses.add(
        responses.POST, "https://opnsense.test/api/firewall/source_nat/apply",
        json={"status": "ok"}, status=200,
    )
    writer = NatWriter(_client(), AuditLog(str(tmp_path / "audit.jsonl")))
    out = writer.create(NatInput(interface="wan", target="1.2.3.4"))
    assert out.ok is True
    assert out.uuid == "u-1"


@responses.activate
def test_nat_writer_create_rolls_back_on_apply_failure(tmp_path: Path):
    responses.add(
        responses.POST, "https://opnsense.test/api/firewall/source_nat/addRule",
        json={"result": "saved", "uuid": "u-2"}, status=200,
    )
    responses.add(
        responses.POST, "https://opnsense.test/api/firewall/source_nat/apply",
        json={"errorMessage": "boom"}, status=500,
    )
    responses.add(
        responses.POST, "https://opnsense.test/api/firewall/source_nat/delRule/u-2",
        json={"result": "deleted"}, status=200,
    )
    writer = NatWriter(_client(), AuditLog(str(tmp_path / "audit.jsonl")))
    out = writer.create(NatInput(interface="wan", target="1.2.3.4"))
    assert out.ok is False
    assert "rolled back" in (out.detail or "")


def test_nat_writer_validates_required_fields(tmp_path: Path):
    writer = NatWriter(_client(), AuditLog(str(tmp_path / "audit.jsonl")))
    with pytest.raises(ValueError):
        writer.create(NatInput(interface="", target="1.2.3.4"))
    with pytest.raises(ValueError):
        writer.create(NatInput(interface="wan", target=""))


# ---- /api/nat route ----------------------------------------------------

@responses.activate
def test_nat_list_payload_ok():
    responses.add(
        responses.GET, "https://opnsense.test/api/firewall/source_nat/searchRule",
        json={"rows": [{"uuid": "u-1", "interface": "wan"}], "total": 1}, status=200,
    )
    status, payload = build_nat_list_payload(HOST)
    assert status == 200
    assert payload["ok"] is True
    assert payload["data"]["total"] == 1


def test_nat_action_refuses_in_read_only_mode(tmp_path: Path):
    status, payload = build_nat_action_payload(HOST, str(tmp_path), {"action": "create"}, read_only=True)
    assert status == 403
    assert payload["error"] == "read_only"


def test_nat_action_rejects_unknown_action(tmp_path: Path):
    status, payload = build_nat_action_payload(HOST, str(tmp_path), {"action": "nuke"})
    assert status == 400


def test_nat_action_create_requires_target(tmp_path: Path):
    status, payload = build_nat_action_payload(
        HOST, str(tmp_path), {"action": "create", "rule": {"interface": "wan"}}
    )
    assert status == 400
    assert payload["error"] in ("validation", "bad_request")


@responses.activate
def test_nat_action_create_then_delete(tmp_path: Path):
    responses.add(
        responses.POST, "https://opnsense.test/api/firewall/source_nat/addRule",
        json={"result": "saved", "uuid": "u-3"}, status=200,
    )
    responses.add(
        responses.POST, "https://opnsense.test/api/firewall/source_nat/apply",
        json={"status": "ok"}, status=200,
    )
    status, payload = build_nat_action_payload(
        HOST, str(tmp_path),
        {"action": "create", "rule": {"interface": "wan", "target": "1.2.3.4"}},
    )
    assert status == 200
    assert payload["data"]["uuid"] == "u-3"

    responses.add(
        responses.POST, "https://opnsense.test/api/firewall/source_nat/delRule/u-3",
        json={"result": "deleted"}, status=200,
    )
    responses.add(
        responses.POST, "https://opnsense.test/api/firewall/source_nat/apply",
        json={"status": "ok"}, status=200,
    )
    status, payload = build_nat_action_payload(
        HOST, str(tmp_path),
        {"action": "delete", "uuid": "u-3"},
    )
    assert status == 200


def test_audit_log_written(tmp_path: Path):
    audit = AuditLog(str(tmp_path / "audit.jsonl"))
    # NatWriter writes through this same path; piggyback on existing test fixtures
    # to assert format invariants.
    from src.writers import AuditEntry
    e = AuditEntry.now(user="plugin", action="nat.create", target="u-x", host="lab",
                       result="ok", duration_ms=12, detail="")
    audit.append(e)
    rows = (tmp_path / "audit.jsonl").read_text().strip().splitlines()
    assert len(rows) == 1
    parsed = json.loads(rows[0])
    assert parsed["action"] == "nat.create"
