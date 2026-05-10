"""Unit tests for the writer framework — mocked, no network."""
from __future__ import annotations

import json
import pathlib

import pytest
import responses

from src.client import OPNsenseClient, OPNsenseHost
from src.client.opnsense_client import _RetryPolicy
from src.writers import (
    AliasInput,
    AliasWriter,
    AuditLog,
    HAVerifier,
    RuleInput,
    RuleWriter,
)
from src.writers.audit import AuditEntry


HOST = OPNsenseHost(name="lab", url="https://opnsense.test", api_key="k", api_secret="s", verify_tls=False)


def _client() -> OPNsenseClient:
    return OPNsenseClient(HOST, retry=_RetryPolicy(attempts=1, base_delay=0.0, max_delay=0.0))


@pytest.fixture
def audit(tmp_path: pathlib.Path) -> AuditLog:
    return AuditLog(str(tmp_path / "audit.jsonl"))


# =========================================================== AuditLog =====

def test_audit_appends_and_tails(tmp_path: pathlib.Path):
    log = AuditLog(str(tmp_path / "a.jsonl"))
    for i in range(5):
        log.append(AuditEntry.now(
            user="u", action="x", target=str(i), host="h",
            result="ok", duration_ms=10, detail="",
        ))
    rows = log.tail(3)
    assert [r.target for r in rows] == ["2", "3", "4"]
    all_rows = list(log.iter_all())
    assert len(all_rows) == 5


def test_audit_tail_on_missing_file(tmp_path: pathlib.Path):
    log = AuditLog(str(tmp_path / "missing.jsonl"))
    assert log.tail() == []


def test_audit_skips_corrupt_lines(tmp_path: pathlib.Path):
    p = tmp_path / "mix.jsonl"
    p.write_text(json.dumps({
        "ts": "2026-05-10T00:00:00Z", "user": "u", "action": "a",
        "target": "t", "host": "h", "result": "ok", "duration_ms": 1, "detail": "",
    }) + "\n" + "not-json\n")
    log = AuditLog(str(p))
    rows = log.tail()
    assert len(rows) == 1
    assert rows[0].action == "a"


# =========================================================== AliasWriter =

@responses.activate
def test_alias_create_happy_path(audit: AuditLog):
    responses.add(
        responses.POST, "https://opnsense.test/api/firewall/alias/addItem",
        json={"result": "saved", "uuid": "abc-123"}, status=200,
    )
    responses.add(
        responses.POST, "https://opnsense.test/api/firewall/alias/reconfigure",
        json={"status": "ok"}, status=200,
    )
    w = AliasWriter(_client(), audit)
    res = w.create(AliasInput(name="test_alias", type="host", content="10.0.0.1"))
    assert res.ok is True
    assert res.uuid == "abc-123"
    # Audit row written
    assert audit.tail()[-1].action == "alias.create"
    assert audit.tail()[-1].result == "ok"


@responses.activate
def test_alias_create_rolls_back_when_reconfigure_fails(audit: AuditLog):
    responses.add(
        responses.POST, "https://opnsense.test/api/firewall/alias/addItem",
        json={"result": "saved", "uuid": "uuid-rollback"}, status=200,
    )
    responses.add(
        responses.POST, "https://opnsense.test/api/firewall/alias/reconfigure",
        json={"message": "boom"}, status=500,
    )
    # Rollback delete of the orphan row
    responses.add(
        responses.POST, "https://opnsense.test/api/firewall/alias/delItem/uuid-rollback",
        json={"result": "deleted"}, status=200,
    )
    w = AliasWriter(_client(), audit)
    res = w.create(AliasInput(name="r", type="host", content="1.1.1.1"))
    assert res.ok is False
    assert "rolled back" in (res.detail or "")
    # Verify the rollback delete was attempted
    delete_calls = [c for c in responses.calls if "delItem" in c.request.url]
    assert delete_calls, "expected rollback delete to be attempted"
    # Audit error row recorded
    assert audit.tail()[-1].result == "error"


@responses.activate
def test_alias_create_no_uuid_in_response(audit: AuditLog):
    responses.add(
        responses.POST, "https://opnsense.test/api/firewall/alias/addItem",
        json={"result": "saved"}, status=200,  # missing uuid
    )
    res = AliasWriter(_client(), audit).create(AliasInput(name="x"))
    assert res.ok is False
    assert "uuid" in res.detail.lower()


@responses.activate
def test_alias_update(audit: AuditLog):
    responses.add(
        responses.POST, "https://opnsense.test/api/firewall/alias/setItem/u-1",
        json={"result": "saved"}, status=200,
    )
    responses.add(
        responses.POST, "https://opnsense.test/api/firewall/alias/reconfigure",
        json={"status": "ok"}, status=200,
    )
    res = AliasWriter(_client(), audit).update("u-1", AliasInput(name="updated"))
    assert res.ok is True
    assert audit.tail()[-1].action == "alias.update"


@responses.activate
def test_alias_delete(audit: AuditLog):
    responses.add(
        responses.POST, "https://opnsense.test/api/firewall/alias/delItem/u-2",
        json={"result": "deleted"}, status=200,
    )
    responses.add(
        responses.POST, "https://opnsense.test/api/firewall/alias/reconfigure",
        json={"status": "ok"}, status=200,
    )
    res = AliasWriter(_client(), audit).delete("u-2")
    assert res.ok is True
    assert audit.tail()[-1].action == "alias.delete"


@responses.activate
def test_alias_search_passes_phrase(audit: AuditLog):
    responses.add(
        responses.GET, "https://opnsense.test/api/firewall/alias/searchItem",
        json={"rows": [{"uuid": "u", "name": "match"}]}, status=200,
    )
    rows = AliasWriter(_client(), audit).search("match")
    assert rows[0]["name"] == "match"


# =========================================================== RuleWriter ==

@responses.activate
def test_rule_create_happy_path(audit: AuditLog):
    responses.add(
        responses.POST, "https://opnsense.test/api/firewall/filter/addRule",
        json={"result": "saved", "uuid": "rule-1"}, status=200,
    )
    responses.add(
        responses.POST, "https://opnsense.test/api/firewall/filter/apply",
        json={"status": "ok"}, status=200,
    )
    w = RuleWriter(_client(), audit)
    res = w.create(RuleInput(interface="wan", action="pass", description="allow https"))
    assert res.ok is True
    assert res.uuid == "rule-1"
    assert audit.tail()[-1].action == "rule.create"


def test_rule_validation_rejects_bad_action(audit: AuditLog):
    w = RuleWriter(_client(), audit)
    with pytest.raises(ValueError, match="action"):
        w.create(RuleInput(interface="wan", action="nope"))


def test_rule_validation_rejects_missing_interface(audit: AuditLog):
    w = RuleWriter(_client(), audit)
    with pytest.raises(ValueError, match="interface"):
        w.create(RuleInput(interface=""))


@responses.activate
def test_rule_create_rolls_back_on_apply_failure(audit: AuditLog):
    responses.add(
        responses.POST, "https://opnsense.test/api/firewall/filter/addRule",
        json={"uuid": "r-bad"}, status=200,
    )
    responses.add(
        responses.POST, "https://opnsense.test/api/firewall/filter/apply",
        json={}, status=500,
    )
    responses.add(
        responses.POST, "https://opnsense.test/api/firewall/filter/delRule/r-bad",
        json={"result": "deleted"}, status=200,
    )
    res = RuleWriter(_client(), audit).create(RuleInput(interface="wan", description="x"))
    assert res.ok is False
    assert "rolled back" in (res.detail or "")


# =========================================================== HAVerifier ==

@responses.activate
def test_ha_verifier_no_peer_is_short_circuit(audit: AuditLog):
    responses.add(
        responses.GET, "https://opnsense.test/api/firewall/alias/searchItem",
        json={"rows": [{"uuid": "u"}]}, status=200,
    )
    ha = HAVerifier(local=_client(), peer=None)
    res = ha.verify("/api/firewall/alias/searchItem")
    assert res.verified is True
    assert res.peer_fingerprint == res.local_fingerprint
    assert "single-node" in res.detail


@responses.activate
def test_ha_verifier_peer_matches():
    responses.add(
        responses.GET, "https://opnsense.test/api/firewall/alias/searchItem",
        json={"rows": [{"uuid": "u", "name": "a"}]}, status=200,
    )
    responses.add(
        responses.POST, "https://opnsense.test/api/core/hasync/syncTo",
        json={"status": "ok"}, status=200,
    )
    responses.add(
        responses.GET, "https://opnsense.peer.test/api/firewall/alias/searchItem",
        json={"rows": [{"uuid": "u", "name": "a"}]}, status=200,
    )
    peer_host = OPNsenseHost(
        name="peer", url="https://opnsense.peer.test", api_key="k", api_secret="s", verify_tls=False,
    )
    ha = HAVerifier(
        local=_client(),
        peer=OPNsenseClient(peer_host, retry=_RetryPolicy(attempts=1, base_delay=0.0, max_delay=0.0)),
    )
    res = ha.verify("/api/firewall/alias/searchItem")
    assert res.triggered is True
    assert res.verified is True


@responses.activate
def test_ha_verifier_peer_diverges():
    responses.add(
        responses.GET, "https://opnsense.test/api/firewall/alias/searchItem",
        json={"rows": [{"uuid": "u-local"}]}, status=200,
    )
    responses.add(
        responses.POST, "https://opnsense.test/api/core/hasync/syncTo",
        json={}, status=200,
    )
    responses.add(
        responses.GET, "https://opnsense.peer.test/api/firewall/alias/searchItem",
        json={"rows": [{"uuid": "u-DIFFERENT"}]}, status=200,
    )
    peer_host = OPNsenseHost(
        name="peer", url="https://opnsense.peer.test", api_key="k", api_secret="s", verify_tls=False,
    )
    ha = HAVerifier(
        local=_client(),
        peer=OPNsenseClient(peer_host, retry=_RetryPolicy(attempts=1, base_delay=0.0, max_delay=0.0)),
    )
    res = ha.verify("/api/firewall/alias/searchItem")
    assert res.triggered is True
    assert res.verified is False
