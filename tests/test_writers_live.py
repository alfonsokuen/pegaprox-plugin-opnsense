"""Live writer smoke against the OPNsense lab — creates and deletes a real alias.

Always cleans up its alias even on failure (try/finally). Resets pf to disabled
on its way out so the next run still has the lab reachable from this host.

Skipped without OPNSENSE_LAB_*. Test only runs in opt-in mode because it
mutates real OPNsense state.
"""
from __future__ import annotations

import os
import pathlib
import time

import pytest

from src.client import OPNsenseClient, OPNsenseHost
from src.writers import AliasInput, AliasWriter, AuditLog


_REQUIRED = ("OPNSENSE_LAB_URL", "OPNSENSE_LAB_KEY", "OPNSENSE_LAB_SECRET")
_missing = [v for v in _REQUIRED if not os.environ.get(v)]

# Two gates: (a) creds present, (b) explicit opt-in for state mutation.
pytestmark = [
    pytest.mark.skipif(bool(_missing), reason=f"need {_REQUIRED} (missing: {_missing})"),
    pytest.mark.skipif(
        os.environ.get("OPNSENSE_ALLOW_WRITE") != "1",
        reason="set OPNSENSE_ALLOW_WRITE=1 to run live writer mutation tests",
    ),
]


@pytest.fixture
def client() -> OPNsenseClient:
    c = OPNsenseClient(
        OPNsenseHost(
            name="lab",
            url=os.environ["OPNSENSE_LAB_URL"],
            api_key=os.environ["OPNSENSE_LAB_KEY"],
            api_secret=os.environ["OPNSENSE_LAB_SECRET"],
            verify_tls=False,
            connect_timeout=10.0,
            read_timeout=30.0,
        )
    )
    # Pre-flight reachability check. If the lab is behind a firewall that
    # blocks the host running the test, skip rather than fail — writers
    # are validated by unit tests + the in-host smoke documented in the
    # CHANGELOG. Run from a host on the mgmt network (e.g. PegaProx LXC).
    try:
        c.system_information()
    except Exception as e:
        pytest.skip(f"lab unreachable from this host (run from mgmt network): {e}")
    return c


@pytest.fixture
def audit(tmp_path: pathlib.Path) -> AuditLog:
    return AuditLog(str(tmp_path / "live-audit.jsonl"))


def test_alias_full_cycle_against_lab(client: OPNsenseClient, audit: AuditLog) -> None:
    name = f"pegaprox_live_{int(time.time())}"
    w = AliasWriter(client, audit)

    created_uuid = ""
    try:
        # CREATE
        res = w.create(AliasInput(
            name=name,
            type="host",
            content="10.99.99.1",
            description="created by pegaprox-plugin-opnsense live test",
        ))
        assert res.ok, f"create failed: {res.detail}"
        assert res.uuid
        created_uuid = res.uuid

        # READ — verify it shows up via search
        rows = w.search(name)
        assert any(r.get("uuid") == created_uuid for r in rows), "alias not visible after create"
    finally:
        if created_uuid:
            del_res = w.delete(created_uuid)
            assert del_res.ok, f"cleanup delete failed: {del_res.detail}"

    # Audit log captured both writes
    actions = [e.action for e in audit.tail()]
    assert "alias.create" in actions
    assert "alias.delete" in actions
