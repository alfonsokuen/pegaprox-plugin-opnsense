"""Live render_metrics smoke against the OPNsense lab."""
from __future__ import annotations

import os

import pytest

from src.client import OPNsenseClient, OPNsenseHost
from src.metrics import render_metrics


_REQUIRED = ("OPNSENSE_LAB_URL", "OPNSENSE_LAB_KEY", "OPNSENSE_LAB_SECRET")
_missing = [v for v in _REQUIRED if not os.environ.get(v)]
pytestmark = pytest.mark.skipif(bool(_missing), reason=f"need {_REQUIRED}")


def test_render_metrics_against_lab() -> None:
    client = OPNsenseClient(
        OPNsenseHost(
            name="lab",
            url=os.environ["OPNSENSE_LAB_URL"],
            api_key=os.environ["OPNSENSE_LAB_KEY"],
            api_secret=os.environ["OPNSENSE_LAB_SECRET"],
            verify_tls=False,
        )
    )
    try:
        client.system_information()
    except Exception as e:
        pytest.skip(f"lab unreachable: {e}")
    body = render_metrics(client, host_label="lab")
    assert 'opnsense_up{host="lab"} 1' in body
    # At least one iface and one service line emitted
    assert "opnsense_iface_rx_bytes_total" in body
    assert "opnsense_service_running" in body
