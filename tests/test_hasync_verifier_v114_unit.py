"""v1.14.0 — robust post-write replication verify.

Covers:
- verify_item(): per-UUID confirmation on peer with retry/backoff for pfSync
  propagation delay.
- verify_revision(): compares config_revision on local vs peer to catch the
  "syncTo returned 200 but didn't actually push" failure mode (brief §9).
- Legacy verify() preserved (backward compat).
"""
from __future__ import annotations

import pytest
import responses

from src.client import OPNsenseClient, OPNsenseHost
from src.client.opnsense_client import _RetryPolicy
from src.writers import HAVerifier


HOST_L = OPNsenseHost(name="lab", url="https://l.test", api_key="k", api_secret="s", verify_tls=False)
HOST_P = OPNsenseHost(name="peer", url="https://p.test", api_key="k", api_secret="s", verify_tls=False)


def _c(host: OPNsenseHost) -> OPNsenseClient:
    return OPNsenseClient(host, retry=_RetryPolicy(attempts=1, base_delay=0.0, max_delay=0.0))


def _ha(monkeypatch) -> HAVerifier:
    # Avoid real sleeps during backoff.
    monkeypatch.setattr("src.writers.hasync_writer.time.sleep", lambda _s: None)
    return HAVerifier(local=_c(HOST_L), peer=_c(HOST_P))


# ====================================================== verify_item =========


@responses.activate
def test_verify_item_found_first_try(monkeypatch):
    responses.add(responses.POST, "https://l.test/api/core/hasync/syncTo", json={}, status=200)
    responses.add(
        responses.GET, "https://p.test/api/firewall/alias/searchItem",
        json={"rows": [{"uuid": "abc-123", "name": "a"}]}, status=200,
    )
    res = _ha(monkeypatch).verify_item(
        search_path="/api/firewall/alias/searchItem",
        uuid_field="uuid",
        uuid_value="abc-123",
    )
    assert res.verified is True
    assert res.triggered is True
    assert res.attempts == 1
    assert "found" in res.detail


@responses.activate
def test_verify_item_found_after_retry(monkeypatch):
    """pfSync propagation lag: peer is stale, then catches up."""
    responses.add(responses.POST, "https://l.test/api/core/hasync/syncTo", json={}, status=200)
    # First two peer fetches: item missing. Third: present.
    responses.add(responses.GET, "https://p.test/api/firewall/alias/searchItem",
                  json={"rows": []}, status=200)
    responses.add(responses.GET, "https://p.test/api/firewall/alias/searchItem",
                  json={"rows": [{"uuid": "other"}]}, status=200)
    responses.add(responses.GET, "https://p.test/api/firewall/alias/searchItem",
                  json={"rows": [{"uuid": "abc-123"}]}, status=200)
    res = _ha(monkeypatch).verify_item(
        "/api/firewall/alias/searchItem", "uuid", "abc-123",
        max_attempts=5, backoff_s=0.01,
    )
    assert res.verified is True
    assert res.attempts == 3


@responses.activate
def test_verify_item_never_found(monkeypatch):
    responses.add(responses.POST, "https://l.test/api/core/hasync/syncTo", json={}, status=200)
    for _ in range(5):
        responses.add(responses.GET, "https://p.test/api/firewall/alias/searchItem",
                      json={"rows": [{"uuid": "other"}]}, status=200)
    res = _ha(monkeypatch).verify_item(
        "/api/firewall/alias/searchItem", "uuid", "abc-123",
        max_attempts=5, backoff_s=0.01,
    )
    assert res.verified is False
    assert res.attempts == 5
    assert "not present" in res.detail


@responses.activate
def test_verify_item_delete_semantics(monkeypatch):
    """When `expect_present=False` (delete flow), success means item is GONE."""
    responses.add(responses.POST, "https://l.test/api/core/hasync/syncTo", json={}, status=200)
    responses.add(responses.GET, "https://p.test/api/firewall/alias/searchItem",
                  json={"rows": []}, status=200)
    res = _ha(monkeypatch).verify_item(
        "/api/firewall/alias/searchItem", "uuid", "abc-123",
        expect_present=False,
    )
    assert res.verified is True
    assert res.attempts == 1


@responses.activate
def test_verify_item_no_peer_short_circuits(monkeypatch):
    ha = HAVerifier(local=_c(HOST_L), peer=None)
    res = ha.verify_item(
        "/api/firewall/alias/searchItem", "uuid", "abc-123",
    )
    assert res.verified is True
    assert res.triggered is False
    assert "single-node" in res.detail


@responses.activate
def test_verify_item_sync_fails(monkeypatch):
    responses.add(responses.POST, "https://l.test/api/core/hasync/syncTo",
                  json={"error": "nope"}, status=500)
    res = _ha(monkeypatch).verify_item(
        "/api/firewall/alias/searchItem", "uuid", "abc-123",
    )
    assert res.verified is False
    assert res.triggered is False
    assert "syncTo failed" in res.detail


@responses.activate
def test_verify_item_peer_fetch_raises(monkeypatch):
    responses.add(responses.POST, "https://l.test/api/core/hasync/syncTo", json={}, status=200)
    # No GET stub → responses raises ConnectionError on the peer fetch.
    res = _ha(monkeypatch).verify_item(
        "/api/firewall/alias/searchItem", "uuid", "abc-123",
        max_attempts=2, backoff_s=0.01,
    )
    assert res.verified is False
    assert "peer fetch failed" in res.detail


# ==================================================== verify_revision ======


@responses.activate
def test_verify_revision_match(monkeypatch):
    responses.add(responses.POST, "https://l.test/api/core/hasync/syncTo", json={}, status=200)
    responses.add(responses.GET, "https://l.test/api/diagnostics/system/system_information",
                  json={"config_revision": "42"}, status=200)
    responses.add(responses.GET, "https://p.test/api/diagnostics/system/system_information",
                  json={"config_revision": "42"}, status=200)
    res = _ha(monkeypatch).verify_revision()
    assert res.verified is True
    assert res.revision_local == "42"
    assert res.revision_peer == "42"


@responses.activate
def test_verify_revision_peer_stale_then_catches_up(monkeypatch):
    responses.add(responses.POST, "https://l.test/api/core/hasync/syncTo", json={}, status=200)
    responses.add(responses.GET, "https://l.test/api/diagnostics/system/system_information",
                  json={"config_revision": "43"}, status=200)
    responses.add(responses.GET, "https://p.test/api/diagnostics/system/system_information",
                  json={"config_revision": "42"}, status=200)
    responses.add(responses.GET, "https://l.test/api/diagnostics/system/system_information",
                  json={"config_revision": "43"}, status=200)
    responses.add(responses.GET, "https://p.test/api/diagnostics/system/system_information",
                  json={"config_revision": "43"}, status=200)
    res = _ha(monkeypatch).verify_revision(max_attempts=3, backoff_s=0.01)
    assert res.verified is True
    assert res.attempts == 2


@responses.activate
def test_verify_revision_peer_never_catches_up(monkeypatch):
    responses.add(responses.POST, "https://l.test/api/core/hasync/syncTo", json={}, status=200)
    for _ in range(3):
        responses.add(responses.GET, "https://l.test/api/diagnostics/system/system_information",
                      json={"config_revision": "43"}, status=200)
        responses.add(responses.GET, "https://p.test/api/diagnostics/system/system_information",
                      json={"config_revision": "42"}, status=200)
    res = _ha(monkeypatch).verify_revision(max_attempts=3, backoff_s=0.01)
    assert res.verified is False
    assert res.revision_local == "43"
    assert res.revision_peer == "42"


# ====================================================== verify_robust =====


@responses.activate
def test_verify_robust_matches_first_try(monkeypatch):
    responses.add(responses.GET, "https://l.test/api/firewall/alias/searchItem",
                  json={"rows": [{"uuid": "u"}]}, status=200)
    responses.add(responses.POST, "https://l.test/api/core/hasync/syncTo", json={}, status=200)
    responses.add(responses.GET, "https://p.test/api/firewall/alias/searchItem",
                  json={"rows": [{"uuid": "u"}]}, status=200)
    res = _ha(monkeypatch).verify_robust("/api/firewall/alias/searchItem")
    assert res.verified is True
    assert res.attempts == 1


@responses.activate
def test_verify_robust_matches_after_propagation(monkeypatch):
    responses.add(responses.GET, "https://l.test/api/firewall/alias/searchItem",
                  json={"rows": [{"uuid": "u"}]}, status=200)
    responses.add(responses.POST, "https://l.test/api/core/hasync/syncTo", json={}, status=200)
    responses.add(responses.GET, "https://p.test/api/firewall/alias/searchItem",
                  json={"rows": []}, status=200)
    responses.add(responses.GET, "https://p.test/api/firewall/alias/searchItem",
                  json={"rows": [{"uuid": "u"}]}, status=200)
    res = _ha(monkeypatch).verify_robust("/api/firewall/alias/searchItem",
                                          max_attempts=3, backoff_s=0.01)
    assert res.verified is True
    assert res.attempts == 2


@responses.activate
def test_verify_robust_diverges_returns_revision_diag(monkeypatch):
    responses.add(responses.GET, "https://l.test/api/firewall/alias/searchItem",
                  json={"rows": [{"uuid": "u"}]}, status=200)
    responses.add(responses.POST, "https://l.test/api/core/hasync/syncTo", json={}, status=200)
    for _ in range(3):
        responses.add(responses.GET, "https://p.test/api/firewall/alias/searchItem",
                      json={"rows": []}, status=200)
    responses.add(responses.GET, "https://l.test/api/diagnostics/system/system_information",
                  json={"config_revision": "9"}, status=200)
    responses.add(responses.GET, "https://p.test/api/diagnostics/system/system_information",
                  json={"config_revision": "8"}, status=200)
    res = _ha(monkeypatch).verify_robust("/api/firewall/alias/searchItem",
                                          max_attempts=3, backoff_s=0.01)
    assert res.verified is False
    assert res.attempts == 3
    assert res.revision_local == "9"
    assert res.revision_peer == "8"
    assert "revision mismatch" in res.detail


# ====================================================== legacy verify ======


@responses.activate
def test_legacy_verify_still_works(monkeypatch):
    """v1.13.x callers must keep working unchanged."""
    responses.add(responses.GET, "https://l.test/api/firewall/alias/searchItem",
                  json={"rows": [{"uuid": "u"}]}, status=200)
    responses.add(responses.POST, "https://l.test/api/core/hasync/syncTo", json={}, status=200)
    responses.add(responses.GET, "https://p.test/api/firewall/alias/searchItem",
                  json={"rows": [{"uuid": "u"}]}, status=200)
    res = _ha(monkeypatch).verify("/api/firewall/alias/searchItem")
    assert res.verified is True
