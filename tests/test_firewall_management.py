"""Exercise the new verified route pipeline and native model contracts."""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from types import SimpleNamespace

import pytest

from src.client import OPNsenseAuthError, OPNsenseError, OPNsenseTimeoutError
from src.routes import firewall
from src.writers.audit import AuditLog, hash_payload
from src.writers.port_forward import PortForwardInput
from src.writers.verified import VerifiedFirewallWriter, matches, selected, validate_uuid

UUID = "06ef0c66-91fb-490a-9345-2fd20b1bad8e"
DNAT = {"interface": "wan", "target": "192.0.2.10", "destination_port": "443", "target_port": "8443"}
RULE = {"interface": "lan", "action": "block", "protocol": "tcp", "destination_port": "25"}
ALIAS = {"name": "LabHosts", "type": "host", "content": "192.0.2.11\n192.0.2.12"}


class Firewall:
    def __init__(self, key="rule"):
        self.host = SimpleNamespace(name="lab")
        self.key = key
        self.rows = {}
        self.calls = []
        self.fail = {}
        self.override_read = None

    def post(self, path, payload):
        self.calls.append(("POST", path, deepcopy(payload)))
        operation = path.rsplit("/", 2)[-2] if path.endswith(UUID) else path.rsplit("/", 1)[-1]
        injected = self.fail.get(operation)
        if injected:
            value = injected.pop(0) if isinstance(injected, list) else injected
            if isinstance(value, Exception):
                raise value
            return value
        if operation.startswith("add"):
            self.rows[UUID] = deepcopy(payload[self.key])
            return {"result": "saved", "uuid": UUID}
        if operation.startswith("set"):
            self.rows[UUID].update(deepcopy(payload[self.key]))
            return {"result": "saved"}
        if operation.startswith("del"):
            del self.rows[UUID]
            return {"result": "deleted"}
        return {"status": "ok"}

    def get(self, path, **params):
        self.calls.append(("GET", path, params))
        if "search" in path:
            return {"rows": [{"uuid": uid, **row} for uid, row in self.rows.items()], "total": len(self.rows)}
        if self.override_read is not None:
            return self.override_read
        return {self.key: deepcopy(self.rows.get(path.rsplit("/", 1)[-1], {}))}


@pytest.mark.parametrize("resource,input_data,key", [("port_forward", DNAT, "rule"), ("rules", RULE, "rule"), ("aliases", ALIAS, "alias")])
def test_crud_full_pipeline(monkeypatch, tmp_path, resource, input_data, key):
    appliance = Firewall(key)
    monkeypatch.setattr(firewall, "OPNsenseClient", lambda host: appliance)
    def action(verb, data=None):
        body = {"action": verb, key: data or input_data}
        if verb != "create":
            body["uuid"] = UUID
            body["revision"] = hash_payload(appliance.rows[UUID])
        return firewall.build_firewall_action_payload(None, str(tmp_path), body, actor="qa-user", resource=resource)
    status, result = action("create")
    result = result["data"]
    assert status == 200 and result["ok"] and result["verified"] and result["applied"]
    assert result["audit"]["user"] == "qa-user"
    status, listing = firewall.build_firewall_list_payload(None, resource)
    row = listing["data"]["aliases" if key == "alias" else "rules"][0]
    assert status == 200 and row["uuid"] == UUID and row["editable"]
    assert row["enabled"] is (resource == "aliases")
    assert action("update", {**input_data, "description": "changed"})[0] == 200
    assert action("delete")[0] == 200
    assert not appliance.rows
    assert len(AuditLog(str(tmp_path / "state" / "audit.jsonl")).tail()) == 6


def test_native_dnat_contract_and_manual_default():
    payload = firewall.parse_payload("port_forward", {**DNAT, "enabled": False, "protocol": "tcp/udp"})["rule"]
    assert payload["disabled"] == "1"
    assert payload["source"] == {"network": "any", "port": ""}
    assert payload["destination"] == {"network": "wanip", "port": "443"}
    assert payload["local-port"] == "8443" and payload["protocol"] == "TCP/UDP"
    assert payload["pass"] == ""
    assert "associated-rule-id" not in payload


@pytest.mark.parametrize("patch", [{"enabled": "false"}, {"target_port": "65536"}, {"destination_port": "400:100"}, {"target_port": "80:90"}, {"sequence": True}, {"interface": ""}, {"filter_association": "allow"}, {"target": []}])
def test_bad_input_never_contacts_upstream(monkeypatch, tmp_path, patch):
    monkeypatch.setattr(firewall, "OPNsenseClient", lambda _: pytest.fail("No API client allowed"))
    status, _ = firewall.build_firewall_action_payload(None, str(tmp_path), {"action": "create", "rule": {**DNAT, **patch}})
    assert status == 400


@pytest.mark.parametrize("body", [None, [], "x", {"action": "update", "uuid": "../apply"}, {"action": "create", "rule": []}])
def test_invalid_body_and_uuid(monkeypatch, tmp_path, body):
    monkeypatch.setattr(firewall, "OPNsenseClient", lambda _: pytest.fail("No API client allowed"))
    assert firewall.build_firewall_action_payload(None, str(tmp_path), body)[0] == 400


def test_read_only_before_validation(monkeypatch, tmp_path):
    monkeypatch.setattr(firewall, "OPNsenseClient", lambda _: pytest.fail("No API client allowed"))
    assert firewall.build_firewall_action_payload(None, str(tmp_path), None, read_only=True)[0] == 403


@pytest.fixture
def writer(tmp_path):
    appliance = Firewall()
    return VerifiedFirewallWriter(appliance, AuditLog(str(tmp_path / "audit.jsonl")), "port_forward")


def test_http_200_validation_failure_is_not_success(writer):
    writer.client.fail["addRule"] = {"result": "failed", "validations": {"rule.target": "Invalid target"}}
    out = writer.execute("create", firewall.parse_payload("port_forward", DNAT))
    assert not out["ok"] and out["error"] == "validation"
    assert out["validations"] and len(writer.client.calls) == 1


def test_apply_reject_rollback_reapplies_and_verifies_absence(writer):
    writer.client.fail["apply"] = [{"status": "failed"}, {"status": "ok"}]
    out = writer.execute("create", firewall.parse_payload("port_forward", DNAT))
    assert not out["ok"] and out["rollback"]["attempted"] and out["rollback"]["verified"]
    assert not writer.client.rows
    assert sum("apply" in path for _, path, _ in writer.client.calls) == 2


def test_rollback_failure_is_visible(writer):
    writer.client.fail["apply"] = {"status": "failed"}
    writer.client.fail["delRule"] = OPNsenseError("delete blocked")
    out = writer.execute("create", firewall.parse_payload("port_forward", DNAT))
    assert not out["ok"] and out["rollback"]["attempted"] and not out["rollback"]["verified"]
    assert "delete blocked" in out["rollback"]["detail"]


@pytest.mark.parametrize("operation", ["addRule", "apply"])
def test_timeout_never_retries_or_blindly_rolls_back(writer, operation):
    writer.client.fail[operation] = OPNsenseTimeoutError("ambiguous timeout")
    out = writer.execute("create", firewall.parse_payload("port_forward", DNAT))
    assert not out["ok"] and out["error"] == "timeout" and not out["rollback"]["attempted"]
    assert sum(operation in path for _, path, _ in writer.client.calls) == 1
    assert not any("delRule" in path for _, path, _ in writer.client.calls)


def test_readback_mismatch_does_not_report_success(writer):
    writer.client.override_read = {"rule": {"target": "192.0.2.99"}}
    out = writer.execute("create", firewall.parse_payload("port_forward", DNAT))
    assert not out["ok"] and out["applied"] and not out["verified"]


def test_ha_requires_matching_content_not_just_uuid(writer, monkeypatch):
    monkeypatch.setattr("src.writers.verified.time.sleep", lambda _: None)
    writer.peer = Firewall()
    writer.peer.rows[UUID] = {"target": "192.0.2.99"}
    out = writer.execute("create", firewall.parse_payload("port_forward", DNAT))
    assert not out["ok"] and out["verified"] and out["error"] == "ha_unverified"
    assert out["sync"]["attempts"] == 6 and not out["sync"]["verified"]
    assert not any("syncTo" in path for _, path, _ in writer.client.calls)


def test_ha_actual_readback_converges(writer):
    writer.peer = Firewall()
    payload = firewall.parse_payload("port_forward", DNAT)
    writer.peer.rows[UUID] = deepcopy(payload["rule"])
    out = writer.execute("create", payload)
    assert out["ok"] and out["sync"]["verified"] and out["sync"]["mode"] == "automatic"


def test_ha_waits_for_initially_missing_object(writer, monkeypatch):
    monkeypatch.setattr("src.writers.verified.time.sleep", lambda _: None)
    payload = firewall.parse_payload("port_forward", DNAT)
    reads = iter([{}, {"rule": payload["rule"]}])
    writer.peer = Firewall()
    writer.peer.get = lambda *args, **kwargs: next(reads)
    out = writer.execute("create", payload)
    assert out["ok"] and out["sync"]["attempts"] == 2


def test_option_dicts_and_alias_multiselect_readback():
    assert selected({"wan": {"selected": 1}, "lan": {"selected": 0}}) == "wan"
    assert matches({"content": {"192.0.2.12": {"selected": 1}, "192.0.2.11": {"selected": 1}}}, {"content": ALIAS["content"]})


@pytest.mark.parametrize("error,status", [(OPNsenseAuthError("403 forbidden"), 401), (OPNsenseError("HTTP 404"), 502)])
def test_unavailable_list_is_not_empty_success(monkeypatch, error, status):
    class Broken(Firewall):
        def get(self, path, **params):
            raise error
    monkeypatch.setattr(firewall, "OPNsenseClient", lambda _: Broken())
    code, out = firewall.build_firewall_list_payload(None)
    assert code == status and not out["ok"]
    assert out.get("supported") is (False if status == 502 else None)


def test_alias_list_never_discloses_credentials(monkeypatch):
    appliance = Firewall("alias")
    appliance.rows[UUID] = {**ALIAS, "username": "private-user", "password": "private-secret", "authtype": "basic"}
    monkeypatch.setattr(firewall, "OPNsenseClient", lambda _: appliance)
    status, out = firewall.build_firewall_list_payload(None, "aliases")
    assert status == 200
    assert "private-user" not in str(out) and "private-secret" not in str(out)
    assert "authtype" not in out["data"]["aliases"][0]


def test_incomplete_search_cannot_verify_deletion(writer):
    writer.client.get = lambda *args, **kwargs: {"rows": [], "total": 50}
    with pytest.raises(OPNsenseError, match="incomplete"):
        writer.verify(UUID, None)


def test_audit_failure_prevents_mutation(writer):
    def fail(_):
        raise OSError("disk full")
    writer.audit.append = fail
    out = writer.execute("create", firewall.parse_payload("port_forward", DNAT))
    assert not out["ok"] and out["error"] == "audit" and not writer.client.calls


@pytest.mark.parametrize("verb", ["update", "delete"])
@pytest.mark.parametrize("revision", [None, "", "0" * 63, "G" * 64, 123])
def test_mutations_require_valid_revision_before_client(monkeypatch, tmp_path, verb, revision):
    monkeypatch.setattr(firewall, "OPNsenseClient", lambda _: pytest.fail("No API client allowed"))
    status, _ = firewall.build_firewall_action_payload(None, str(tmp_path), {
        "action": verb, "uuid": UUID, "revision": revision, "rule": DNAT})
    assert status == 400


@pytest.mark.parametrize("resource,input_data,key", [("port_forward", DNAT, "rule"), ("rules", RULE, "rule"), ("aliases", ALIAS, "alias")])
@pytest.mark.parametrize("verb", ["update", "delete"])
def test_stale_revision_conflict_before_mutation(monkeypatch, tmp_path, resource, input_data, key, verb):
    appliance = Firewall(key)
    appliance.rows[UUID] = firewall.parse_payload(resource, input_data)[key]
    monkeypatch.setattr(firewall, "OPNsenseClient", lambda _: appliance)
    _, listing = firewall.build_firewall_list_payload(None, resource)
    row = listing["data"]["aliases" if key == "alias" else "rules"][0]
    assert row["revision"] == hash_payload(appliance.rows[UUID])
    # A hidden advanced property also invalidates the form revision.
    appliance.rows[UUID]["advanced_concurrent_change"] = "new value"
    appliance.calls.clear()
    status, result = firewall.build_firewall_action_payload(None, str(tmp_path), {
        "action": verb, "uuid": UUID, "revision": row["revision"], key: input_data}, resource=resource)
    assert status == 409 and result["error"] == "conflict"
    assert not result["data"]["applied"] and not result["data"]["verified"]
    assert not any(method == "POST" for method, _, _ in appliance.calls)


@pytest.mark.parametrize("peer_still_present", [False, True])
def test_rollback_ha_requires_peer_absence(writer, monkeypatch, peer_still_present):
    monkeypatch.setattr("src.writers.verified.time.sleep", lambda _: None)
    writer.peer = Firewall()
    if peer_still_present:
        writer.peer.rows[UUID] = {"target": "192.0.2.10"}
    writer.client.fail["apply"] = [{"status": "failed"}, {"status": "ok"}]
    result = writer.execute("create", firewall.parse_payload("port_forward", DNAT))
    rollback = result["rollback"]
    assert rollback["local_verified"] is True
    assert rollback["peer_verified"] is (not peer_still_present)
    assert rollback["verified"] is (not peer_still_present)


def test_rollback_peer_unreachable_is_not_verified(writer, monkeypatch):
    monkeypatch.setattr("src.writers.verified.time.sleep", lambda _: None)
    writer.peer = Firewall()
    def unavailable(*args, **kwargs):
        raise OPNsenseAuthError("Peer forbidden")
    writer.peer.get = unavailable
    writer.client.fail["apply"] = [{"status": "failed"}, {"status": "ok"}]
    result = writer.execute("create", firewall.parse_payload("port_forward", DNAT))
    rollback = result["rollback"]
    assert rollback["local_verified"] and not rollback["peer_verified"] and not rollback["verified"]
    assert "Peer forbidden" in rollback["detail"]


def test_two_local_writers_cannot_both_overwrite_same_revision(writer):
    payload = firewall.parse_payload("port_forward", DNAT)
    writer.client.rows[UUID] = deepcopy(payload["rule"])
    revision = hash_payload(writer.client.rows[UUID])
    other = VerifiedFirewallWriter(writer.client, writer.audit, "port_forward")
    payload["rule"]["descr"] = "changed"
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(writer.execute, "update", payload, UUID, revision)
        second = pool.submit(other.execute, "update", payload, UUID, revision)
        results = [first.result(), second.result()]
    assert sum(result["ok"] for result in results) == 1
    assert sum(result.get("error") == "conflict" for result in results) == 1
    assert sum("setRule" in path for _, path, _ in writer.client.calls) == 1


def test_uuids_are_canonicalized_and_uppercase_presence_not_missed(writer):
    assert validate_uuid(UUID.upper()) == UUID
    writer.client.rows[UUID] = {"target": "192.0.2.10"}
    assert not writer.verify(UUID.upper(), None)
    writer.client.rows = {UUID.upper(): {"target": "192.0.2.10"}}
    assert not writer.verify(UUID, None)


def test_uppercase_uuid_update_targets_canonical_path(writer):
    payload = firewall.parse_payload("port_forward", DNAT)
    writer.client.rows[UUID] = deepcopy(payload["rule"])
    revision = hash_payload(writer.client.rows[UUID])
    payload["rule"]["descr"] = "updated"
    result = writer.execute("update", payload, UUID.upper(), revision)
    assert result["ok"] and result["uuid"] == UUID
    assert any(path.endswith("/setRule/" + UUID) for _, path, _ in writer.client.calls)


def test_new_firewall_rules_are_disabled_unless_explicitly_enabled():
    assert firewall.parse_payload("rules", RULE)["rule"]["enabled"] == "0"
    assert firewall.parse_payload("port_forward", DNAT)["rule"]["disabled"] == "1"
    assert PortForwardInput(**DNAT).to_payload()["rule"]["disabled"] == "1"
    assert firewall.parse_payload("rules", {**RULE, "enabled": True})["rule"]["enabled"] == "1"
    assert firewall.parse_payload("port_forward", {**DNAT, "enabled": True})["rule"]["disabled"] == "0"


def test_ha_defaults_allow_seven_and_half_seconds_waits(writer, monkeypatch):
    waits = []
    monkeypatch.setattr("src.writers.verified.time.sleep", waits.append)
    writer.peer = Firewall()
    result = writer._sync(UUID, {"target": "192.0.2.10"})
    assert not result["verified"] and result["attempts"] == 6
    assert waits == [0.5, 1.0, 1.5, 2.0, 2.5]


def test_ha_retry_configuration_is_used(writer, monkeypatch):
    waits = []
    monkeypatch.setattr("src.writers.verified.time.sleep", waits.append)
    configured = VerifiedFirewallWriter(writer.client, writer.audit, "port_forward", peer=Firewall(),
        ha_verify_attempts=4, ha_verify_backoff=0.25)
    result = configured._sync(UUID, {"target": "192.0.2.10"})
    assert not result["verified"] and result["attempts"] == 4
    assert waits == [0.25, 0.5, 0.75]


@pytest.mark.parametrize("config", [{"ha_verify_attempts": 0}, {"ha_verify_attempts": 11},
    {"ha_verify_attempts": True}, {"ha_verify_backoff": -1}, {"ha_verify_backoff": 3},
    {"ha_verify_backoff": float("nan")}, {"ha_verify_backoff": True}])
def test_ha_retry_configuration_is_bounded(writer, config):
    with pytest.raises(ValueError):
        VerifiedFirewallWriter(writer.client, writer.audit, "port_forward", **config)


@pytest.mark.parametrize("protocol", ["tcp", "udp", "tcp/udp", "icmp", "any"])
def test_filter_protocol_case_normalization_readback(protocol):
    # Official ProtocolField::setValue applies UPPER for Filter, preserving
    # any, and DNat.xml overrides ChangeCase to lower. Comparison accepts both.
    expected = "any" if protocol == "any" else protocol.upper()
    assert matches({"protocol": expected}, {"protocol": protocol})
    assert matches({"protocol": protocol}, {"protocol": expected})


@pytest.mark.parametrize("association", ["", "pass", "rule"])
def test_dnat_filter_association_matches_official_model(association):
    assert firewall.parse_payload("port_forward", {**DNAT, "filter_association": association})["rule"]["pass"] == association
