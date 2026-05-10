"""E2E browser smoke test against a live PegaProx host with the plugin.

Opt-in: set `RUN_E2E=1` and provide creds via env to run. Otherwise the
whole module is skipped so the regular unit suite stays fast (<1s).

Required env:
  RUN_E2E=1
  PEGAPROX_URL=https://pegasus.idkmanager.com
  PEGAPROX_USER=alfonso
  PEGAPROX_PASS=...

What it does:
  1. Logs in via /api/auth/login (XHR header + same-origin).
  2. Loads the plugin UI iframe (/api/plugins/opnsense/api/ui).
  3. Visits every tab — overview / network / vpn / logs / nat / dns /
     dhcp / wg — clicking the tab button and waiting for the grid to
     render at least one section card.
  4. Collects console errors and asserts none are emitted during the
     navigation. Warnings are tolerated.

This is designed to run in CI behind a tunnel/VPN that can reach
pegasus.idkmanager.com. Locally it doubles as a regression check after
deploying a new plugin version.

Known caveats:
- When run back-to-back, the two tests may interfere on the live host
  (PegaProx rate-limits rapid logins from the same IP). Run them
  separately with `-k test_e2e_login_and_visit_all_tabs` /
  `-k test_e2e_round_trip` if needed.
- PegaProx ships `session_id` with SameSite=Strict; the helper relaxes
  it to Lax inside the test context so `page.goto()` sends the cookie.
  This is a test-only relaxation; production users navigate via
  in-page links that never hit the Strict guard.
"""
from __future__ import annotations

import os

import pytest

RUN_E2E = os.environ.get("RUN_E2E") == "1"
PEGAPROX_URL = os.environ.get("PEGAPROX_URL", "")
PEGAPROX_USER = os.environ.get("PEGAPROX_USER", "")
PEGAPROX_PASS = os.environ.get("PEGAPROX_PASS", "")

pytestmark = [
    pytest.mark.skipif(not RUN_E2E, reason="set RUN_E2E=1 to run browser e2e"),
    pytest.mark.skipif(
        not (PEGAPROX_URL and PEGAPROX_USER and PEGAPROX_PASS),
        reason="set PEGAPROX_URL / PEGAPROX_USER / PEGAPROX_PASS",
    ),
]

TABS = ("overview", "network", "vpn", "logs", "nat", "dns", "dhcp", "wg")


@pytest.fixture(scope="module")
def _pw():
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:  # pragma: no cover
        pytest.skip("install: pip install playwright && playwright install chromium")
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        yield browser
        browser.close()


@pytest.fixture
def browser_context(_pw):
    """Fresh context per test — isolates cookies/storage between scenarios."""
    ctx = _pw.new_context(ignore_https_errors=True)
    yield ctx
    ctx.close()


def _login(page, base: str, user: str, password: str) -> None:
    """Authenticate against PegaProx and relax session_id SameSite so a
    subsequent top-level page.goto() into the plugin UI includes the cookie.
    PegaProx ships session_id with SameSite=Strict, which Chromium blocks on
    page.goto() (treated as a cross-site nav by Playwright). Relaxing to Lax
    only inside the test context is safe — real users navigate via in-page
    links from /home, which never trip the Strict guard.
    """
    page.goto(f"{base}/", wait_until="domcontentloaded")
    page.evaluate(
        """async ({user, password}) => {
            const r = await fetch('/api/auth/login', {
                method: 'POST',
                credentials: 'same-origin',
                headers: {'Content-Type':'application/json','X-Requested-With':'XMLHttpRequest'},
                body: JSON.stringify({username: user, password}),
            });
            if (!r.ok) throw new Error('login failed ' + r.status);
            const j = await r.json();
            if (!j.success) throw new Error('login rejected: ' + JSON.stringify(j));
        }""",
        {"user": user, "password": password},
    )
    ctx = page.context
    cookies = ctx.cookies()
    for c in cookies:
        if c.get("name") == "session_id":
            c["sameSite"] = "Lax"
    ctx.clear_cookies()
    ctx.add_cookies(cookies)


def test_e2e_login_and_visit_all_tabs(browser_context):
    base = PEGAPROX_URL.rstrip("/")
    page = browser_context.new_page()

    console_errors: list[str] = []
    page.on("console", lambda msg: console_errors.append(msg.text) if msg.type == "error" else None)

    _login(page, base, PEGAPROX_USER, PEGAPROX_PASS)
    page.goto(f"{base}/api/plugins/opnsense/api/ui#overview", wait_until="domcontentloaded")
    page.wait_for_function(
        "() => document.querySelectorAll('[role=tab]').length >= 8",
        timeout=30_000,
    )

    for tab in TABS:
        page.click(f'[data-tab="{tab}"]')
        page.wait_for_function(
            "(t) => document.querySelector('[role=tab][aria-selected=true]')?.dataset?.tab === t",
            arg=tab, timeout=10_000,
        )
        # Wait for at least one section card to render (or the busy state to clear)
        page.wait_for_function(
            "() => document.querySelector('#grid')?.children.length >= 1",
            timeout=10_000,
        )

    # Filter known-benign console noise: favicon, font preloads, and the
    # pre-login 401 burst from the initial home-page fetch (PegaProx probes
    # /api/auth/check before the session cookie lands).
    def _benign(m: str) -> bool:
        lo = m.lower()
        return (
            "favicon" in lo
            or "preload" in lo
            or "status of 401" in lo
            # PegaProx checkSession races a logout call on tab unload.
            or "logout request failed" in lo
        )
    real = [m for m in console_errors if not _benign(m)]
    assert real == [], f"console errors during tab walk: {real}"


@pytest.mark.skipif(
    os.environ.get("RUN_E2E_WRITE") != "1",
    reason="set RUN_E2E_WRITE=1 to enable write-path smoke (creates+deletes a real host override)",
)
def test_e2e_round_trip_unbound_host(browser_context):
    """Optional write-path smoke: create + delete a host override via plugin REST.

    Gated separately from read-path because writes against a live OPNsense
    apply the change immediately. Lab/dev only — never run against prod.
    """
    base = PEGAPROX_URL.rstrip("/")
    page = browser_context.new_page()
    _login(page, base, PEGAPROX_USER, PEGAPROX_PASS)
    # Navigate to the plugin UI so the session cookie is fully established
    # in the same origin before issuing API writes.
    page.goto(f"{base}/api/plugins/opnsense/api/ui#overview")
    page.wait_for_selector('[role=tablist]', state="attached", timeout=30_000)

    result = page.evaluate(
        """async () => {
            const headers = {'Content-Type':'application/json','X-Requested-With':'XMLHttpRequest'};
            const create = await (await fetch('/api/plugins/opnsense/api/unbound', {
                method: 'POST', credentials: 'same-origin', headers,
                body: JSON.stringify({action:'create', host: {
                    hostname: 'e2e-smoke', domain: 'lab.local',
                    server: '192.168.1.123', description: 'pytest e2e',
                }}),
            })).json();
            if (!create.ok) return {step: 'create', error: create};
            const uuid = create.data.uuid;
            const del = await (await fetch('/api/plugins/opnsense/api/unbound', {
                method: 'POST', credentials: 'same-origin', headers,
                body: JSON.stringify({action:'delete', uuid}),
            })).json();
            return {step: 'done', uuid, del};
        }""",
    )
    assert result.get("step") == "done", f"round-trip failed: {result}"
    assert result["del"]["ok"] is True
