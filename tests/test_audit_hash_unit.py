"""Unit tests for v1.9.0 audit-log payload hashes.

The AuditEntry gained a `payload_sha256` field that captures a tamper-
evident hash of the canonical-JSON payload sent to OPNsense. The hash is
deterministic across runs (sorted keys, no whitespace) and excluded from
the entry when payload is None.
"""
from __future__ import annotations

import json
from pathlib import Path

import responses

from src.client import OPNsenseClient, OPNsenseHost
from src.client.opnsense_client import _RetryPolicy
from src.writers import AliasInput, AliasWriter, AuditLog
from src.writers.audit import AuditEntry, hash_payload

HOST = OPNsenseHost(name="lab", url="https://opnsense.test", api_key="k", api_secret="s", verify_tls=False)


def _client() -> OPNsenseClient:
    return OPNsenseClient(HOST, retry=_RetryPolicy(attempts=1, base_delay=0.0, max_delay=0.0))


def test_hash_payload_is_canonical():
    # Same content, different key order → same hash
    a = hash_payload({"a": 1, "b": {"x": 2, "y": 3}})
    b = hash_payload({"b": {"y": 3, "x": 2}, "a": 1})
    assert a == b
    assert len(a) == 64  # sha256 hex

    # Different content → different hash
    c = hash_payload({"a": 1, "b": {"x": 2, "y": 4}})
    assert a != c


def test_hash_payload_none_returns_empty():
    assert hash_payload(None) == ""


def test_audit_entry_now_includes_payload_sha256():
    e = AuditEntry.now(
        user="u", action="x.create", target="t", host="h",
        result="ok", duration_ms=1, payload_sha256="deadbeef",
    )
    assert e.payload_sha256 == "deadbeef"


def test_audit_entry_default_payload_sha256_empty():
    e = AuditEntry.now(
        user="u", action="x.delete", target="t", host="h",
        result="ok", duration_ms=1,
    )
    assert e.payload_sha256 == ""


def test_audit_log_round_trip_with_payload_sha(tmp_path: Path):
    log = AuditLog(str(tmp_path / "a.jsonl"))
    e1 = AuditEntry.now(user="u", action="alias.create", target="uuid-1",
                        host="lab", result="ok", duration_ms=42,
                        payload_sha256="abc123")
    log.append(e1)
    rows = log.tail(10)
    assert len(rows) == 1
    assert rows[0].payload_sha256 == "abc123"


def test_audit_log_tolerates_pre_v1_9_entries(tmp_path: Path):
    # Simulate a JSONL written by an older plugin version without payload_sha256.
    p = tmp_path / "a.jsonl"
    p.write_text(json.dumps({
        "ts": "2026-01-01T00:00:00Z", "user": "u", "action": "alias.create",
        "target": "uuid-old", "host": "lab", "result": "ok", "duration_ms": 10,
        "detail": "",
    }) + "\n", encoding="utf-8")
    log = AuditLog(str(p))
    rows = log.tail(10)
    assert len(rows) == 1
    assert rows[0].payload_sha256 == ""  # defaulted


def test_audit_log_tolerates_future_unknown_fields(tmp_path: Path):
    # Future v1.10 might add new fields; old code must not crash.
    p = tmp_path / "a.jsonl"
    p.write_text(json.dumps({
        "ts": "2026-12-01T00:00:00Z", "user": "u", "action": "alias.create",
        "target": "uuid-future", "host": "lab", "result": "ok", "duration_ms": 10,
        "detail": "", "payload_sha256": "ff", "future_field": "ignored",
    }) + "\n", encoding="utf-8")
    log = AuditLog(str(p))
    rows = log.tail(10)
    assert len(rows) == 1
    assert rows[0].payload_sha256 == "ff"


@responses.activate
def test_writer_create_records_payload_sha256(tmp_path: Path):
    responses.add(
        responses.POST, "https://opnsense.test/api/firewall/alias/addItem",
        json={"result": "saved", "uuid": "a-1"}, status=200,
    )
    responses.add(
        responses.POST, "https://opnsense.test/api/firewall/alias/reconfigure",
        json={"status": "ok"}, status=200,
    )
    log_path = tmp_path / "a.jsonl"
    log = AuditLog(str(log_path))
    w = AliasWriter(_client(), log, actor="plugin")
    payload = AliasInput(name="qa_smoke", type="host", content="1.2.3.4", description="x")
    out = w.create(payload)
    assert out.ok and out.uuid == "a-1"
    rows = log.tail(10)
    # last row is the success record with the hash; earlier rows (if any) are errors.
    ok_row = [r for r in rows if r.result == "ok" and r.action == "alias.create"]
    assert len(ok_row) == 1
    expected = hash_payload(payload.to_payload())
    assert ok_row[0].payload_sha256 == expected
    assert len(ok_row[0].payload_sha256) == 64
