"""Live smoke against the OPNsense lab.

Skipped by default. Enable by exporting:
  OPNSENSE_LAB_URL=https://190.160.10.108
  OPNSENSE_LAB_KEY=...
  OPNSENSE_LAB_SECRET=...

Recommended source for the creds: SOPS vault `opnsense.lab.{api_key,api_secret}`.
Never commit credentials.
"""
from __future__ import annotations

import os

import pytest

from src.client import OPNsenseClient, OPNsenseHost


_REQUIRED = ("OPNSENSE_LAB_URL", "OPNSENSE_LAB_KEY", "OPNSENSE_LAB_SECRET")
_missing = [v for v in _REQUIRED if not os.environ.get(v)]

pytestmark = pytest.mark.skipif(
    bool(_missing),
    reason=f"set {', '.join(_REQUIRED)} to run live smoke (missing: {_missing})",
)


@pytest.fixture
def client() -> OPNsenseClient:
    return OPNsenseClient(
        OPNsenseHost(
            name="lab",
            url=os.environ["OPNSENSE_LAB_URL"],
            api_key=os.environ["OPNSENSE_LAB_KEY"],
            api_secret=os.environ["OPNSENSE_LAB_SECRET"],
            verify_tls=False,  # self-signed lab cert
        )
    )


def test_system_information_live(client: OPNsenseClient) -> None:
    info = client.system_information()
    assert "name" in info
    assert any("OPNsense" in v for v in info.get("versions", []))
