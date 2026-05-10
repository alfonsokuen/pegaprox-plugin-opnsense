"""Unit tests for OPNsenseClient — mocked, no network."""
from __future__ import annotations

import pytest
import responses

from src.client import (
    OPNsenseAuthError,
    OPNsenseClient,
    OPNsenseError,
    OPNsenseHost,
    OPNsenseTimeoutError,
)
from src.client.opnsense_client import _RetryPolicy


HOST = OPNsenseHost(
    name="lab",
    url="https://opnsense.test",
    api_key="key",
    api_secret="secret",
    verify_tls=False,
    connect_timeout=1.0,
    read_timeout=1.0,
)


def _client(retry: _RetryPolicy | None = None) -> OPNsenseClient:
    return OPNsenseClient(HOST, retry=retry or _RetryPolicy(attempts=3, base_delay=0.0, max_delay=0.0))


# ----- happy path ----------------------------------------------------------

@responses.activate
def test_get_returns_json():
    responses.add(
        responses.GET,
        "https://opnsense.test/api/diagnostics/system/system_information",
        json={"name": "OPNsense.internal", "versions": ["OPNsense 26.1.2_5-amd64"]},
        status=200,
    )
    out = _client().system_information()
    assert out["name"] == "OPNsense.internal"
    assert any("26.1" in v for v in out["versions"])


@responses.activate
def test_post_returns_json():
    responses.add(
        responses.POST,
        "https://opnsense.test/api/firewall/alias/addItem",
        json={"result": "saved", "uuid": "abc"},
        status=200,
    )
    out = _client().post("/api/firewall/alias/addItem", {"alias": {"name": "x"}})
    assert out["result"] == "saved"


# ----- auth ----------------------------------------------------------------

@responses.activate
def test_401_raises_auth_error():
    responses.add(
        responses.GET,
        "https://opnsense.test/api/x",
        json={"message": "no"},
        status=401,
    )
    with pytest.raises(OPNsenseAuthError):
        _client().get("/api/x")


@responses.activate
def test_403_raises_auth_error():
    responses.add(
        responses.GET,
        "https://opnsense.test/api/x",
        json={"message": "forbidden"},
        status=403,
    )
    with pytest.raises(OPNsenseAuthError):
        _client().get("/api/x")


@responses.activate
def test_basic_auth_header_present():
    responses.add(
        responses.GET,
        "https://opnsense.test/api/x",
        json={"ok": True},
        status=200,
    )
    _client().get("/api/x")
    sent = responses.calls[0].request
    assert sent.headers.get("Authorization", "").startswith("Basic ")


# ----- retries -------------------------------------------------------------

@responses.activate
def test_get_retries_on_502_then_succeeds():
    responses.add(responses.GET, "https://opnsense.test/api/x", status=502)
    responses.add(responses.GET, "https://opnsense.test/api/x", status=503)
    responses.add(responses.GET, "https://opnsense.test/api/x", json={"ok": True}, status=200)
    out = _client().get("/api/x")
    assert out == {"ok": True}
    assert len(responses.calls) == 3


@responses.activate
def test_get_gives_up_after_attempts():
    for _ in range(3):
        responses.add(responses.GET, "https://opnsense.test/api/x", status=503)
    with pytest.raises(OPNsenseError):
        _client().get("/api/x")
    assert len(responses.calls) == 3


@responses.activate
def test_post_does_not_retry():
    responses.add(responses.POST, "https://opnsense.test/api/x", status=502)
    with pytest.raises(OPNsenseError):
        _client().post("/api/x", {})
    assert len(responses.calls) == 1, "POST must not retry — writers own reconcile"


# ----- timeouts ------------------------------------------------------------

@responses.activate
def test_connection_error_exhausts_retries():
    from requests.exceptions import ConnectionError as RequestsConnectionError

    responses.add(
        responses.GET,
        "https://opnsense.test/api/x",
        body=RequestsConnectionError("boom"),
    )
    with pytest.raises(OPNsenseTimeoutError):
        _client().get("/api/x")


# ----- input validation ----------------------------------------------------

def test_http_url_rejected():
    with pytest.raises(ValueError, match="HTTPS"):
        OPNsenseClient(
            OPNsenseHost(name="x", url="http://nope", api_key="k", api_secret="s")
        )


@responses.activate
def test_non_json_response_raises():
    responses.add(
        responses.GET,
        "https://opnsense.test/api/x",
        body="<html>not json</html>",
        status=200,
        content_type="text/html",
    )
    with pytest.raises(OPNsenseError, match="non-JSON"):
        _client().get("/api/x")


@responses.activate
def test_path_normalisation():
    # Path without leading slash should still hit the right URL.
    responses.add(
        responses.GET,
        "https://opnsense.test/api/x",
        json={"ok": True},
        status=200,
    )
    _client().get("api/x")
    assert len(responses.calls) == 1
