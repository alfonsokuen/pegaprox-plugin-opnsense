from copy import deepcopy
import pytest

from src.routes import firewall
from src.writers.audit import AuditLog, hash_payload
from src.writers.verified import VerifiedFirewallWriter
from tests.test_firewall_management import Firewall, UUID, ALIAS, DNAT


@pytest.mark.parametrize(
    "resource,key,data",
    [
        ("aliases", "alias", ALIAS),
        ("rules", "rule", {"interface": "wan"}),
        ("port_forward", "rule", DNAT),
    ],
)
def test_summary_uses_one_search_and_never_loads_detail(
    monkeypatch, resource, key, data
):
    node = Firewall(key)
    node.rows[UUID] = data
    monkeypatch.setattr(firewall, "OPNsenseClient", lambda _: node)
    code, out = firewall.build_firewall_list_payload(None, resource, summary=True)
    assert code == 200 and len(node.calls) == 1 and "search" in node.calls[0][1]
    row = out["data"]["aliases" if key == "alias" else "rules"][0]
    assert row["uuid"] == UUID and row["editable"] and row["detail_required"]
    assert "revision" not in row


def test_detail_loads_single_canonical_object_without_secrets(monkeypatch):
    node = Firewall("alias")
    node.rows[UUID] = {
        **ALIAS,
        "password": "private-secret",
        "advanced_setting": "retained",
    }
    monkeypatch.setattr(firewall, "OPNsenseClient", lambda _: node)
    code, out = firewall.build_firewall_detail_payload(None, "aliases", UUID)
    assert code == 200 and len(node.calls) == 1 and "getItem" in node.calls[0][1]
    assert out["data"]["item"]["revision"] == hash_payload(node.rows[UUID])
    assert (
        "private-secret" not in str(out)
        and "advanced_setting" not in out["data"]["item"]
    )


@pytest.mark.parametrize("uuid", [None, "../apply", "lockout_0"])
def test_invalid_detail_never_contacts_firewall(monkeypatch, uuid):
    monkeypatch.setattr(
        firewall, "OPNsenseClient", lambda _: pytest.fail("No upstream request")
    )
    code, _ = firewall.build_firewall_detail_payload(None, "aliases", uuid)
    assert code == 400


def test_alias_counters_do_not_make_editor_revision_stale(tmp_path):
    node = Firewall("alias")
    node.rows[UUID] = firewall.parse_payload("aliases", ALIAS)["alias"]
    node.rows[UUID].update(eval_match="1", last_updated="old", in_pass_b="100")
    writer = VerifiedFirewallWriter(
        node, AuditLog(str(tmp_path / "audit.jsonl")), "aliases"
    )
    revision = hash_payload(writer.get(UUID))
    node.rows[UUID].update(eval_match="2", last_updated="new", in_pass_b="200")
    out = writer.execute(
        "update",
        firewall.parse_payload("aliases", {**ALIAS, "description": "edited"}),
        UUID,
        revision,
    )
    assert out["ok"] and out["applied"]


def test_real_alias_change_still_conflicts_with_old_revision(tmp_path):
    node = Firewall("alias")
    node.rows[UUID] = deepcopy(ALIAS)
    writer = VerifiedFirewallWriter(
        node, AuditLog(str(tmp_path / "audit.jsonl")), "aliases"
    )
    revision = hash_payload(writer.get(UUID))
    node.rows[UUID]["advanced_setting"] = "changed"
    out = writer.execute("delete", uuid=UUID, revision=revision)
    assert out["error"] == "conflict" and not any(c[0] == "POST" for c in node.calls)
