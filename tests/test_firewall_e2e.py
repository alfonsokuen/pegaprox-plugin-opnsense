"""Opt-in browser -> plugin handlers -> HTTPS OPNsense simulator integration.

RUN_LOCAL_E2E=1 .venv/Scripts/python -m pytest tests/test_firewall_e2e.py -q
Requires playwright (and chromium), Flask, waitress and cryptography. No live host or
credentials are used. Only host authentication and unrelated read endpoints
are fixtures; management requests traverse the production client and writers.
"""
from __future__ import annotations

import copy
import importlib.util
import json
import os
from pathlib import Path
import sys
import threading
import types
from uuid import uuid4

import pytest

pytestmark = pytest.mark.skipif(os.getenv("RUN_LOCAL_E2E") != "1", reason="set RUN_LOCAL_E2E=1")
ROOT = Path(__file__).resolve().parents[1]
PREFIX = "/api/plugins/opnsense/api"


@pytest.fixture(scope="module")
def browser():
    from playwright.sync_api import sync_playwright
    with sync_playwright() as pw:
        args = ["--log-net-log=" + os.environ["E2E_NETLOG"]] if os.getenv("E2E_NETLOG") else []
        browser = pw.chromium.launch(headless=True, args=args)
        yield browser
        browser.close()


@pytest.fixture
def stack(tmp_path, monkeypatch):
    from flask import Flask, jsonify, request, send_file
    from werkzeug.serving import make_server
    create_server = pytest.importorskip("waitress", reason="install requirements-e2e.txt").create_server

    # State is deliberately independent of the writer's implementation.
    state = types.SimpleNamespace(rows={k: {} for k in ("d_nat", "filter", "alias")},
        applied={k: {} for k in ("d_nat", "filter", "alias")}, calls=[],
        reject_validation=False, reject_apply=False, reject_reads=False, reject_delete=False,
        lose_create_response=False, readonly=False, permitted=True)
    fw = Flask("opnsense_simulator")

    @fw.route("/api/firewall/<controller>/<action>", defaults={"uuid": ""}, methods=["GET", "POST"])
    @fw.route("/api/firewall/<controller>/<action>/<uuid>", methods=["GET", "POST"])
    def firewall(controller, action, uuid):
        assert request.authorization.username == "e2e-key"
        assert request.authorization.password == "e2e-secret"
        state.calls.append((request.method, controller, action, uuid))
        rows = state.rows[controller]
        key = "alias" if controller == "alias" else "rule"
        if action.startswith("search"):
            if state.reject_reads:
                return jsonify(error="API unavailable"), 404
            return jsonify(rows=[dict(value, uuid=id) for id, value in rows.items()], total=len(rows))
        if action.startswith("get"):
            return jsonify({key: rows.get(uuid, {})})
        if action in ("apply", "reconfigure"):
            if state.reject_apply:
                state.reject_apply = False
                return jsonify(status="failed")
            state.applied[controller] = copy.deepcopy(rows)
            return jsonify(status="ok")
        if action.startswith(("add", "set")):
            if state.reject_validation:
                state.reject_validation = False
                return jsonify(result="failed", validations={key + ".target": "Invalid target from simulator"})
            value = request.get_json()[key]
            if action.startswith("add"):
                uuid = str(uuid4())
            elif uuid not in rows:
                return jsonify(result="failed")
            rows[uuid] = copy.deepcopy(value)
            if state.lose_create_response:
                state.lose_create_response = False
                return jsonify(error="simulated gateway timeout after save"), 504
            return jsonify(result="saved", uuid=uuid)
        if action.startswith("del"):
            if state.reject_delete:
                return jsonify(result="failed")
            rows.pop(uuid, None)
            return jsonify(result="deleted")
        return jsonify(error="unsupported simulator operation"), 404

    fw_server = make_server("127.0.0.1", 0, fw, threaded=True, ssl_context="adhoc")
    fw_thread = threading.Thread(target=fw_server.serve_forever, daemon=True)
    fw_thread.start()
    spec = importlib.util.spec_from_file_location("firewall_e2e_plugin", ROOT / "__init__.py")
    plugin = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(plugin)
    monkeypatch.setattr(plugin, "PLUGIN_DIR", str(tmp_path))
    monkeypatch.setattr(plugin, "_load_config", lambda: {
        "read_only": state.readonly, "cluster_mode": "off", "opnsense_hosts": [{
            "name": "local-simulator", "url": f"https://127.0.0.1:{fw_server.server_port}",
            "api_key": "e2e-key", "api_secret": "e2e-secret", "verify_tls": False}]})
    host_auth = types.ModuleType("pegaprox.utils.auth")
    def require_auth(perms):
        assert perms == ["plugins.manage"]
        return lambda fn: lambda: fn() if state.permitted else ("denied", 403)
    host_auth.require_auth = require_auth
    monkeypatch.setitem(sys.modules, "pegaprox.utils.auth", host_auth)
    app = Flask("plugin_e2e")
    app.add_url_rule(PREFIX + "/ui", view_func=lambda: send_file(ROOT / "opnsense.html"))
    for name in ("port_forward", "rules", "aliases"):
        app.add_url_rule(PREFIX + "/" + name, endpoint=name,
            view_func=getattr(plugin, "_h_" + name), methods=["GET", "POST"])
    @app.get(PREFIX + "/<endpoint>")
    def unrelated_reads(endpoint):
        return jsonify(ok=True, data={"hosts_configured": 1, "cluster_mode": False,
            "rules": [], "mappings": [], "supported": True})
    @app.get("/favicon.ico")
    def favicon():
        return "", 204
    # A real HTTP/1.1 WSGI server keeps connections alive. Werkzeug closes each
    # response; Chromium's parallel reconnect burst can hit Windows loopback
    # TCP_CONNECT OS error 10060 before any request reaches Flask (netlog).
    # Keep the simulator HTTPS and all application handlers unchanged.
    app_server = create_server(app, host="127.0.0.1", port=0, threads=4, asyncore_loop_timeout=0.1)
    app_stop = threading.Event()
    def serve_app():
        try:
            while not app_stop.is_set():
                app_server.asyncore.loop(timeout=0.1, map=app_server._map, count=1)
        finally:
            # Close from the event-loop thread, not during Windows select().
            app_server.task_dispatcher.shutdown()
            for dispatcher in list(app_server._map.values()):
                dispatcher.close()
    app_thread = threading.Thread(target=serve_app, daemon=True)
    app_thread.start()
    state.url = f"http://127.0.0.1:{app_server.effective_port}{PREFIX}"
    state.audit_path = tmp_path / "state" / "audit.jsonl"
    yield state
    app_stop.set()
    fw_server.shutdown()
    app_thread.join(timeout=3)
    fw_thread.join(timeout=3)
    assert not app_thread.is_alive(), "HTTP fixture did not stop"


@pytest.fixture
def page(browser, stack):
    context = browser.new_context(viewport={"width": 1440, "height": 1000})
    page = context.new_page()
    page.runtime_errors = []
    page.console_errors = []
    page.network_failures = []
    page.on("requestfailed", lambda request: page.network_failures.append((request.url, request.failure)))
    page.on("pageerror", lambda error: page.runtime_errors.append(str(error)))
    page.on("console", lambda message: page.console_errors.append(message.text) if message.type == "error" else None)
    page.on("dialog", lambda dialog: dialog.accept())
    yield page
    assert page.runtime_errors == []
    context.close()


def open_tab(page, stack, key, theme="corp-dark"):
    from playwright.sync_api import expect
    tab = "nat" if key == "portForward" else "firewall"
    page.goto(stack.url + f"/ui?theme={theme}#{tab}")
    expect(page.locator(f'[data-tab="{tab}"]')).to_have_attribute("aria-selected", "true")
    form = page.locator(f"#{key}-form")
    expect(form).to_be_visible()
    try:
        expect(form.get_by_role("button", name="Crear", exact=True)).to_be_enabled()
    except AssertionError as exc:
        raise AssertionError(f"{exc}\nNetwork failures: {page.network_failures}\nConsole: {page.console_errors}\nForm: {form.inner_text()}") from exc
    expect(page.locator("#grid")).to_have_attribute("aria-busy", "false")
    return form


def fill_dnat(page, description="e2e DNAT"):
    for name, value in {"destination_net": "192.0.2.10", "destination_port": "8443",
                        "target": "198.51.100.20", "target_port": "443", "description": description}.items():
        page.locator("#portForward-" + name).fill(value)


def submit(page, form, endpoint, label="Crear"):
    with page.expect_response(lambda response: response.url.endswith("/" + endpoint)
                              and response.request.method == "POST") as response:
        form.get_by_role("button", name=label, exact=True).click()
    return response.value


@pytest.mark.parametrize("key,controller,endpoint", [
    ("portForward", "d_nat", "port_forward"),
    ("firewallRules", "filter", "rules"),
    ("firewallAliases", "alias", "aliases"),
])
def test_gui_crud_persists_and_applies(page, stack, key, controller, endpoint):
    from playwright.sync_api import expect
    form = open_tab(page, stack, key)
    if key == "portForward":
        fill_dnat(page)
    elif key == "firewallAliases":
        page.locator("#firewallAliases-name").fill("e2e_hosts")
        page.locator("#firewallAliases-content").fill("198.51.100.20\n198.51.100.21")
    page.locator(f"#{key}-description").fill("e2e original")
    response = submit(page, form, endpoint)
    assert response.status == 200, response.text()
    expect(form.get_by_role("status")).to_contain_text("Cambio aplicado y verificado")
    assert len(stack.rows[controller]) == 1
    assert stack.applied[controller] == stack.rows[controller]
    uuid, saved = next(iter(stack.rows[controller].items()))
    assert saved["disabled" if controller == "d_nat" else "enabled"] == ("1" if controller in ("d_nat", "alias") else "0")
    page.get_by_role("button", name="Editar e2e_hosts" if controller == "alias" else "Editar e2e original", exact=True).click()
    expect(form.get_by_role("button", name="Guardar cambios")).to_be_visible()
    expect(page.locator(f"#{key}-description")).to_have_value("e2e original")
    page.locator(f"#{key}-description").fill("e2e edited")
    assert submit(page, form, endpoint, "Guardar cambios").status == 200
    expect(form.get_by_role("status")).to_contain_text("Cambio aplicado y verificado")
    assert stack.rows[controller][uuid]["descr" if controller == "d_nat" else "description"] == "e2e edited"
    assert stack.applied[controller] == stack.rows[controller]
    with page.expect_response(lambda response: response.url.endswith("/" + endpoint) and response.request.method == "POST") as response:
        page.get_by_role("button", name="Eliminar e2e_hosts" if controller == "alias" else "Eliminar e2e edited", exact=True).click()
    assert response.value.status == 200
    expect(form.get_by_role("status")).to_contain_text("Cambio aplicado y verificado")
    assert stack.rows[controller] == stack.applied[controller] == {}
    audit = [json.loads(line) for line in stack.audit_path.read_text().splitlines()]
    assert [item["result"] for item in audit] == ["started", "ok"] * 3
    assert page.console_errors == []


@pytest.mark.parametrize("failure,code", [("reject_validation", 422), ("reject_apply", 502)])
def test_failed_write_is_visible_and_keeps_draft(page, stack, failure, code):
    from playwright.sync_api import expect
    form = open_tab(page, stack, "portForward")
    fill_dnat(page, "retain this draft")
    setattr(stack, failure, True)
    response = submit(page, form, "port_forward")
    assert response.status == code
    expect(form.get_by_role("alert")).to_be_visible()
    expect(form.get_by_role("alert")).to_contain_text("Actualiza la lista")
    expect(page.locator("#portForward-description")).to_have_value("retain this draft")
    expect(page.locator("#portForward-target_port")).to_have_value("443")
    assert form.get_by_role("status").count() == 0
    assert stack.rows["d_nat"] == stack.applied["d_nat"] == {}
    response_body = response.json()
    result = response_body.get("data", response_body)
    if failure == "reject_apply":
        assert result["rollback"]["verified"] is True
    assert not result["ok"] if "ok" in result else not response_body["ok"]
    expect(form.get_by_role("button", name="Crear", exact=True)).to_be_enabled()
    # Chromium reports deliberate failed HTTP requests as console errors.
    assert all(f"status of {code}" in message for message in page.console_errors)


@pytest.mark.parametrize("failure", ["rollback_rejected", "create_reply_lost"])
def test_uncertain_create_cannot_be_submitted_twice(page, stack, failure):
    from playwright.sync_api import expect
    form = open_tab(page, stack, "portForward")
    fill_dnat(page, "uncertain creation")
    if failure == "rollback_rejected":
        stack.reject_apply = stack.reject_delete = True
    else:
        stack.lose_create_response = True
    response = submit(page, form, "port_forward")
    assert response.status == 502
    expect(form.get_by_role("alert")).to_be_visible()
    expect(form.get_by_role("button", name="Crear", exact=True)).to_be_disabled()
    expect(page.locator("#portForward-description")).to_have_value("uncertain creation")
    assert len(stack.rows["d_nat"]) == 1
    before = [call for call in stack.calls if call[0] == "POST"]
    page.locator("#btn-refresh").click()
    expect(page.locator("#grid")).to_have_attribute("aria-busy", "false")
    expect(form.get_by_role("button", name="Crear", exact=True)).to_be_disabled()
    expect(form.get_by_role("alert")).to_be_visible()
    # Submitting by keyboard or requestSubmit must also obey the barrier.
    form.evaluate("form => form.requestSubmit()")
    expect(form.get_by_role("button", name="Crear", exact=True)).to_be_disabled()
    assert [call for call in stack.calls if call[0] == "POST"] == before
    page.locator("#portForward-reconcile").click()
    expect(form.get_by_role("button", name="Crear", exact=True)).to_be_enabled()
    expect(page.locator("#portForward-description")).to_have_value("")
    assert len(stack.rows["d_nat"]) == 1
    assert [call for call in stack.calls if call[0] == "POST"] == before
    assert all("status of 502" in message for message in page.console_errors)


@pytest.mark.parametrize("gate", ["readonly", "permission"])
def test_readonly_and_role_enforced_in_ui_and_handler(page, stack, gate):
    from playwright.sync_api import expect
    if gate == "readonly":
        stack.readonly = True
    else:
        stack.permitted = False
    page.goto(stack.url + "/ui#firewall")
    form = page.locator("#firewallRules-form")
    expect(form.get_by_role("status")).to_contain_text("solo lectura")
    expect(form.get_by_role("button", name="Crear", exact=True)).to_be_disabled()
    before = list(stack.calls)
    response = page.request.post(stack.url + "/rules", data={"action": "create", "rule": {"interface": "wan"}})
    assert response.status == 403
    assert response.json()["error"] == ("read_only" if gate == "readonly" else "forbidden")
    assert stack.calls == before
    assert page.console_errors == []


def test_invalid_port_never_reaches_firewall(page, stack):
    from playwright.sync_api import expect
    form = open_tab(page, stack, "portForward")
    fill_dnat(page)
    page.locator("#portForward-target_port").fill("99999")
    before = list(stack.calls)
    response = submit(page, form, "port_forward")
    assert response.status == 400
    expect(form.get_by_role("alert")).to_contain_text("target_port")
    expect(page.locator("#portForward-target_port")).to_have_value("99999")
    assert stack.calls == before
    assert all("status of 400" in message for message in page.console_errors)


def test_stale_edit_cannot_overwrite_concurrent_change(page, stack):
    from playwright.sync_api import expect
    form = open_tab(page, stack, "firewallRules")
    page.locator("#firewallRules-description").fill("original rule")
    assert submit(page, form, "rules").status == 200
    expect(form.get_by_role("status")).to_contain_text("Cambio aplicado y verificado")
    page.get_by_role("button", name="Editar original rule", exact=True).click()
    expect(form.get_by_role("button", name="Guardar cambios")).to_be_visible()
    uuid = next(iter(stack.rows["filter"]))
    stack.rows["filter"][uuid]["enabled"] = "1"
    stack.rows["filter"][uuid]["description"] = "changed by another administrator"
    stack.applied["filter"] = copy.deepcopy(stack.rows["filter"])
    before = [call for call in stack.calls if call[0] == "POST"]
    page.locator("#firewallRules-description").fill("stale browser draft")
    response = submit(page, form, "rules", "Guardar cambios")
    assert response.status == 409
    expect(form.get_by_role("alert")).to_be_visible()
    expect(page.locator("#firewallRules-description")).to_have_value("stale browser draft")
    assert stack.rows["filter"][uuid]["enabled"] == "1"
    assert stack.rows["filter"][uuid]["description"] == "changed by another administrator"
    assert [call for call in stack.calls if call[0] == "POST"] == before
    assert all("status of 409" in message for message in page.console_errors)


def test_unavailable_api_never_enables_write(page, stack):
    from playwright.sync_api import expect
    stack.reject_reads = True
    page.goto(stack.url + "/ui#firewall")
    expect(page.locator("#grid")).to_have_attribute("aria-busy", "false")
    for key in ("firewallRules", "firewallAliases"):
        form = page.locator(f"#{key}-form")
        expect(form.get_by_role("button", name="Crear", exact=True)).to_be_disabled()
        expect(form.get_by_role("status")).to_contain_text("deshabilitada")
    expect(page.locator(".managed-table [role=alert]")).to_have_count(2)
    assert all(call[0] == "GET" for call in stack.calls)
    assert all("status of 502" in message for message in page.console_errors)


@pytest.mark.parametrize("theme,css", [("corp-dark", None), ("corp-light", "theme-light"), ("cloud", "theme-cloud")])
def test_mobile_themes_keyboard_and_no_viewport_overflow(page, stack, theme, css):
    from playwright.sync_api import expect
    page.set_viewport_size({"width": 390, "height": 844})
    open_tab(page, stack, "portForward", theme)
    if css:
        expect(page.locator("html")).to_have_class(css)
    fill_dnat(page, "mobile draft")
    page.locator("#portForward-description").press("Tab")
    expect(page.locator("#portForward-enabled")).to_be_focused()
    overflow = page.evaluate("""() => ({width: innerWidth, scroll: document.documentElement.scrollWidth,
        elements: [...document.querySelectorAll('body *')].filter(e => e.getBoundingClientRect().right > innerWidth + 1)
        .slice(0, 15).map(e => ({tag: e.tagName, id: e.id, css: e.className, right: e.getBoundingClientRect().right}))})""")
    assert overflow["scroll"] <= overflow["width"], f"mobile page overflows horizontally: {overflow}"
    assert page.console_errors == []
    directory = os.getenv("E2E_ARTIFACT_DIR")
    if directory:
        Path(directory).mkdir(parents=True, exist_ok=True)
        page.screenshot(path=str(Path(directory) / f"dnat-mobile-{theme}.png"), full_page=True, animations="disabled")
