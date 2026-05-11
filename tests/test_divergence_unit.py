"""Unit tests for compute_divergence."""
from __future__ import annotations

from src.divergence import compute_divergence


def _empty_snap() -> dict:
    return {
        "system": {"config_revision": "1.0", "version": "26.1.2", "product_id": "OPNsense"},
        "carp": {"role": "master", "enabled": True, "maintenance_mode": False, "vhids": []},
        "hasync": {"enabled": True, "pfsync_interface": "vtnet1", "pfsync_version": "1400",
                   "sync_compatibility": "1400"},
        "services": {"items": []},
        "gateways": [],
        "interfaces": [],
        "certs": {"expiring_soon": []},
    }


def test_identical_snapshots_yield_no_divergence():
    a = _empty_snap()
    b = _empty_snap()
    b["carp"] = {**b["carp"], "role": "backup"}
    assert compute_divergence(a, b) == []


def test_split_brain_two_masters_is_error():
    a = _empty_snap()
    b = _empty_snap()
    # both master
    divs = compute_divergence(a, b)
    assert any(d["category"] == "carp" and d["severity"] == "error" for d in divs)


def test_config_revision_drift():
    a = _empty_snap()
    b = _empty_snap()
    b["carp"] = {**b["carp"], "role": "backup"}
    b["system"]["config_revision"] = "1.1"
    divs = compute_divergence(a, b)
    assert any(d["category"] == "system" and d["key"] == "config_revision"
               and d["severity"] == "warning" for d in divs)


def test_service_running_state_differs():
    a = _empty_snap()
    b = _empty_snap()
    b["carp"] = {**b["carp"], "role": "backup"}
    a["services"]["items"] = [{"name": "unbound", "running": True}]
    b["services"]["items"] = [{"name": "unbound", "running": False}]
    divs = compute_divergence(a, b)
    flagged = [d for d in divs if d["category"] == "services" and d["key"] == "unbound"]
    assert len(flagged) == 1
    assert flagged[0]["severity"] == "warning"
    assert flagged[0]["a"] is True and flagged[0]["b"] is False


def test_pfsync_disabled_on_one_side_is_error():
    a = _empty_snap()
    b = _empty_snap()
    b["carp"] = {**b["carp"], "role": "backup"}
    b["hasync"] = {**b["hasync"], "enabled": False}
    divs = compute_divergence(a, b)
    assert any(d["category"] == "hasync" and d["key"] == "enabled"
               and d["severity"] == "error" for d in divs)


def test_interface_link_state_mismatch():
    a = _empty_snap()
    b = _empty_snap()
    b["carp"] = {**b["carp"], "role": "backup"}
    a["interfaces"] = [{"name": "wan", "link": "up"}]
    b["interfaces"] = [{"name": "wan", "link": "down"}]
    divs = compute_divergence(a, b)
    assert any(d["category"] == "interfaces" and d["key"] == "wan" for d in divs)


def test_gateway_status_mismatch():
    a = _empty_snap()
    b = _empty_snap()
    b["carp"] = {**b["carp"], "role": "backup"}
    a["gateways"] = [{"name": "WAN_DHCP", "status": "online"}]
    b["gateways"] = [{"name": "WAN_DHCP", "status": "offline"}]
    divs = compute_divergence(a, b)
    assert any(d["category"] == "gateways" and d["key"] == "WAN_DHCP" for d in divs)


def test_cert_present_on_one_side_only():
    a = _empty_snap()
    b = _empty_snap()
    b["carp"] = {**b["carp"], "role": "backup"}
    a["certs"]["expiring_soon"] = [{"fingerprint": "aabbcc", "descr": "lan-cert"}]
    divs = compute_divergence(a, b)
    flagged = [d for d in divs if d["category"] == "certs" and d["key"] == "aabbcc"]
    assert len(flagged) == 1


def test_severity_ordering():
    a = _empty_snap()
    b = _empty_snap()
    # cause one error (pfsync), one warning (gateway), one info (maintenance flip)
    b["carp"] = {**b["carp"], "role": "backup", "maintenance_mode": True}
    b["hasync"] = {**b["hasync"], "enabled": False}
    a["gateways"] = [{"name": "WAN", "status": "online"}]
    b["gateways"] = [{"name": "WAN", "status": "offline"}]
    divs = compute_divergence(a, b)
    severities = [d["severity"] for d in divs]
    # error before warning before info
    rank = {"error": 0, "warning": 1, "info": 2}
    assert severities == sorted(severities, key=rank.__getitem__)


def test_maintenance_mode_flag_is_info():
    a = _empty_snap()
    b = _empty_snap()
    b["carp"] = {**b["carp"], "role": "backup", "maintenance_mode": True}
    divs = compute_divergence(a, b)
    assert any(d["category"] == "carp" and d["key"] == "maintenance_mode"
               and d["severity"] == "info" for d in divs)
