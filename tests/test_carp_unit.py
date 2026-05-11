"""Unit tests for collect_carp_status (v1.13.1: getVipStatus-only)."""
from __future__ import annotations

import responses

from src.client import OPNsenseClient, OPNsenseHost
from src.client.opnsense_client import _RetryPolicy
from src.collectors.carp import _classify_role, _primary_vhid, collect_carp_status

HOST = OPNsenseHost(name="x", url="https://opn.test", api_key="k", api_secret="s", verify_tls=False)


def _client() -> OPNsenseClient:
    return OPNsenseClient(HOST, retry=_RetryPolicy(attempts=1, base_delay=0, max_delay=0))


def _v(vhid: str, status: str, advskew: str = "0") -> dict:
    return {"vhid": vhid, "interface": "lan", "ipaddr": "10.0.0.1",
            "status": status, "advbase": "1", "advskew": advskew}


def test_classify_role_disabled_when_no_vhids():
    assert _classify_role(enabled=False, maintenance=False, vhids=[]) == "disabled"


def test_classify_role_maintenance_forces_backup():
    assert _classify_role(enabled=True, maintenance=True, vhids=[_v("1", "MASTER")]) == "backup"


def test_classify_role_master_when_primary_master():
    assert _classify_role(enabled=True, maintenance=False, vhids=[
        _v("1", "MASTER"), _v("4", "BACKUP"),
    ]) == "master"


def test_classify_role_backup_when_primary_backup_even_with_master_higher():
    """NODOA prod scenario: LAN VHID 1 = BACKUP, LAN_OFI_HA VHID 4 = MASTER.
    Node-role tracks the primary (lowest VHID) VIP."""
    assert _classify_role(enabled=True, maintenance=False, vhids=[
        _v("1", "BACKUP", advskew="0"),
        _v("4", "MASTER", advskew="0"),
    ]) == "backup"


def test_classify_role_disabled_when_all_disabled():
    assert _classify_role(enabled=True, maintenance=False, vhids=[
        _v("1", "DISABLED"), _v("4", "DISABLED"),
    ]) == "disabled"


def test_primary_vhid_picks_lowest_vhid():
    primary = _primary_vhid([_v("4", "MASTER"), _v("1", "BACKUP")])
    assert primary["vhid"] == "1"


def test_primary_vhid_ignores_disabled_rows():
    primary = _primary_vhid([_v("1", "DISABLED"), _v("4", "MASTER")])
    assert primary["vhid"] == "4"


@responses.activate
def test_collect_carp_status_prod_nodoa_shape():
    """Reproduces the live NODOA payload captured 2026-05-11."""
    responses.add(
        responses.GET, "https://opn.test/api/diagnostics/interface/getVipStatus",
        json={
            "total": 2, "rowCount": 2, "current": 1,
            "rows": [
                {"interface": "LAN", "vhid": "1", "advbase": "1", "advskew": "0",
                 "subnet": "190.160.10.1", "status": "BACKUP", "mode": "carp",
                 "status_txt": "BACKUP", "vhid_txt": "1 (freq. 1/0)"},
                {"interface": "LAN_OFI_HA", "vhid": "4", "advbase": "1", "advskew": "0",
                 "subnet": "192.168.30.1", "status": "MASTER", "mode": "carp",
                 "status_txt": "MASTER", "vhid_txt": "4 (freq. 1/0)"},
            ],
            "carp": {
                "demotion": "-540",
                "allow": "1",
                "maintenancemode": False,
                "status_msg": "CARP has detected a problem and this unit has been demoted to BACKUP status.",
            },
        }, status=200,
    )
    out = collect_carp_status(_client())
    assert out["role"] == "backup"  # primary VIP (VHID 1) is BACKUP
    assert out["enabled"] is True
    assert out["maintenance_mode"] is False
    assert out["demotion"] == -540
    assert "demoted to BACKUP" in out["status_msg"]
    assert len(out["vhids"]) == 2


@responses.activate
def test_collect_carp_status_prod_nodob_master():
    responses.add(
        responses.GET, "https://opn.test/api/diagnostics/interface/getVipStatus",
        json={
            "rows": [
                {"interface": "LAN", "vhid": "1", "advbase": "1", "advskew": "100",
                 "subnet": "190.160.10.1", "status": "MASTER", "mode": "carp"},
                {"interface": "LAN_OFI_HA", "vhid": "4", "advbase": "1", "advskew": "100",
                 "subnet": "192.168.30.1", "status": "DISABLED", "mode": "carp"},
            ],
            "carp": {"demotion": "-1300", "allow": "1", "maintenancemode": False, "status_msg": ""},
        }, status=200,
    )
    out = collect_carp_status(_client())
    assert out["role"] == "master"
    assert out["enabled"] is True
    assert out["demotion"] == -1300


@responses.activate
def test_collect_carp_status_filters_non_carp_vips():
    responses.add(
        responses.GET, "https://opn.test/api/diagnostics/interface/getVipStatus",
        json={"rows": [
            {"vhid": "1", "status": "MASTER", "mode": "carp"},
            {"vhid": "", "status": "", "mode": "alias"},
        ], "carp": {}}, status=200,
    )
    out = collect_carp_status(_client())
    assert len(out["vhids"]) == 1
    assert out["vhids"][0]["vhid"] == "1"


@responses.activate
def test_collect_carp_status_no_carp_configured():
    """A single-host OPNsense with no CARP VIPs returns empty rows."""
    responses.add(
        responses.GET, "https://opn.test/api/diagnostics/interface/getVipStatus",
        json={"rows": [], "carp": {}}, status=200,
    )
    out = collect_carp_status(_client())
    assert out["role"] == "disabled"
    assert out["enabled"] is False
    assert out["vhids"] == []


@responses.activate
def test_collect_carp_status_tolerates_endpoint_404():
    responses.add(
        responses.GET, "https://opn.test/api/diagnostics/interface/getVipStatus",
        json={}, status=404,
    )
    out = collect_carp_status(_client())
    assert out["role"] == "disabled"
    assert out["enabled"] is False
