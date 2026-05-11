"""Unit tests for collect_carp_status."""
from __future__ import annotations

import responses

from src.client import OPNsenseClient, OPNsenseHost
from src.client.opnsense_client import _RetryPolicy
from src.collectors.carp import _classify_role, collect_carp_status

HOST = OPNsenseHost(name="x", url="https://opn.test", api_key="k", api_secret="s", verify_tls=False)


def _client() -> OPNsenseClient:
    return OPNsenseClient(HOST, retry=_RetryPolicy(attempts=1, base_delay=0, max_delay=0))


def test_classify_role_disabled():
    assert _classify_role(enabled=False, maintenance=False, vhids=[]) == "disabled"


def test_classify_role_maintenance_forces_backup():
    assert _classify_role(enabled=True, maintenance=True, vhids=[
        {"vhid": "1", "interface": "wan", "ipaddr": "x", "status": "MASTER",
         "advbase": "1", "advskew": "0"},
    ]) == "backup"


def test_classify_role_all_master():
    vhids = [
        {"vhid": "1", "interface": "wan", "ipaddr": "10.0.0.1", "status": "MASTER",
         "advbase": "1", "advskew": "0"},
        {"vhid": "2", "interface": "lan", "ipaddr": "10.0.1.1", "status": "MASTER",
         "advbase": "1", "advskew": "0"},
    ]
    assert _classify_role(enabled=True, maintenance=False, vhids=vhids) == "master"


def test_classify_role_split_is_unknown():
    vhids = [
        {"vhid": "1", "interface": "wan", "ipaddr": "10.0.0.1", "status": "MASTER",
         "advbase": "1", "advskew": "0"},
        {"vhid": "2", "interface": "lan", "ipaddr": "10.0.1.1", "status": "BACKUP",
         "advbase": "1", "advskew": "0"},
    ]
    assert _classify_role(enabled=True, maintenance=False, vhids=vhids) == "unknown"


def test_classify_role_all_backup():
    vhids = [
        {"vhid": "1", "interface": "wan", "ipaddr": "10.0.0.1", "status": "BACKUP",
         "advbase": "1", "advskew": "100"},
    ]
    assert _classify_role(enabled=True, maintenance=False, vhids=vhids) == "backup"


@responses.activate
def test_collect_carp_status_master_node():
    responses.add(
        responses.GET, "https://opn.test/api/diagnostics/interface/getCarpStatus",
        json={"carp_enabled": "1", "maintenance_mode": "0"}, status=200,
    )
    responses.add(
        responses.GET, "https://opn.test/api/diagnostics/interface/getVipStatus",
        json={"rows": [
            {"vhid": "1", "interface": "wan", "ipaddr": "190.160.10.108", "status": "MASTER",
             "advbase": "1", "advskew": "0", "mode": "carp"},
            {"vhid": "2", "interface": "lan", "ipaddr": "192.168.1.1", "status": "MASTER",
             "advbase": "1", "advskew": "0", "mode": "carp"},
        ]}, status=200,
    )
    out = collect_carp_status(_client())
    assert out["role"] == "master"
    assert out["enabled"] is True
    assert out["maintenance_mode"] is False
    assert len(out["vhids"]) == 2


@responses.activate
def test_collect_carp_status_filters_non_carp_vips():
    responses.add(
        responses.GET, "https://opn.test/api/diagnostics/interface/getCarpStatus",
        json={"carp_enabled": "1", "maintenance_mode": "0"}, status=200,
    )
    responses.add(
        responses.GET, "https://opn.test/api/diagnostics/interface/getVipStatus",
        json={"rows": [
            {"vhid": "1", "status": "MASTER", "mode": "carp"},
            {"vhid": "", "status": "", "mode": "alias"},  # not CARP — must be skipped
        ]}, status=200,
    )
    out = collect_carp_status(_client())
    assert len(out["vhids"]) == 1
    assert out["vhids"][0]["vhid"] == "1"


@responses.activate
def test_collect_carp_status_tolerates_missing_endpoints():
    responses.add(
        responses.GET, "https://opn.test/api/diagnostics/interface/getCarpStatus",
        json={}, status=404,
    )
    responses.add(
        responses.GET, "https://opn.test/api/diagnostics/interface/getVipStatus",
        json={}, status=404,
    )
    out = collect_carp_status(_client())
    assert out["role"] == "disabled"
    assert out["enabled"] is False
    assert out["vhids"] == []


@responses.activate
def test_collect_carp_status_disabled_node():
    responses.add(
        responses.GET, "https://opn.test/api/diagnostics/interface/getCarpStatus",
        json={"carp_enabled": "0", "maintenance_mode": "0"}, status=200,
    )
    responses.add(
        responses.GET, "https://opn.test/api/diagnostics/interface/getVipStatus",
        json={"rows": []}, status=200,
    )
    out = collect_carp_status(_client())
    assert out["role"] == "disabled"
    assert out["enabled"] is False
