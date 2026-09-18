"""Chromium -> actual plugin handlers -> HTTPS stateful OPNsense simulator.

Opt in with RUN_LOCAL_E2E=1; install requirements-e2e.txt and Chromium.
The only host stub is PegaProx authorization. No browser route interception.
"""
import copy
import importlib.util
import os
from pathlib import Path
import shutil
import sys
import threading
import types
from uuid import uuid4

import pytest

pytestmark = pytest.mark.skipif(os.getenv('RUN_LOCAL_E2E') != '1', reason='set RUN_LOCAL_E2E=1')
ROOT = Path(__file__).resolve().parents[1]
PREFIX = '/api/plugins/opnsense/api'


@pytest.fixture(scope='module')
def ws_browser():
    from playwright.sync_api import sync_playwright
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        yield browser
        browser.close()


@pytest.fixture
def ws_stack(tmp_path, monkeypatch):
    from flask import Flask, jsonify, request
    from waitress import create_server
    from werkzeug.serving import make_server
    from src.management.catalog import RESOURCES
    from src.management.operations import OPERATIONS

    state = types.SimpleNamespace(rows={key: {} for key in RESOURCES}, calls=[],
        requests=[], readonly=False, permitted=True, reject_save=False, reject_apply=False, unavailable=False)
    firewall = Flask('workspace_firewall')

    def defaults(spec):
        result = {}
        for field in spec['fields']:
            name = field['name']
            result[name] = field.get('default', '0' if field['kind'] == 'boolean' else '')
        if spec['id'] == 'wireguard_servers':
            result['peers'] = {'peer-a': {'value': 'Laboratorio A', 'selected': 0},
                               'peer-b': {'value': 'Laboratorio B', 'selected': 0}}
        return result

    @firewall.route('/api/<path:path>', methods=['GET', 'POST'])
    def upstream(path):
        path = '/api/' + path
        assert request.authorization.username == 'test-key'
        state.calls.append((request.method, path, dict(request.args)))
        if state.unavailable:
            return jsonify(error='not supported'), 404
        if path == '/api/wireguard/service/status':
            return jsonify(status='running')
        if path == '/api/core/firmware/check':
            return jsonify(status='ok')
        for spec in RESOURCES.values():
            if spec.get('apply') == path:
                if state.reject_apply:
                    state.reject_apply = False
                    return jsonify(status='failed')
                return jsonify(status='ok')
            if not path.startswith(spec['base'] + '/'):
                continue
            relative = path[len(spec['base']) + 1:]
            action, _, uuid = relative.partition('/')
            rows = state.rows[spec['id']]
            if action == spec.get('search'):
                query = request.args.get('searchPhrase', '').lower()
                filtered = [dict(value, uuid=key) for key, value in rows.items()
                            if not query or query in str(value).lower()]
                size, page = int(request.args.get('rowCount', 50)), int(request.args.get('current', 1))
                return jsonify(rows=filtered[(page - 1) * size:page * size], total=len(filtered))
            if action == spec.get('get'):
                if spec.get('singleton'):
                    return jsonify({spec['key']: rows.get('settings', defaults(spec))})
                return jsonify({spec['key']: rows.get(uuid, {}) if uuid else defaults(spec)})
            if action in (spec.get('add'), spec.get('set')):
                if state.reject_save:
                    state.reject_save = False
                    return jsonify(result='failed', validations={'name': 'Rejected by simulator'})
                uuid = 'settings' if spec.get('singleton') else uuid or str(uuid4())
                rows[uuid] = copy.deepcopy(request.get_json()[spec['key']])
                return jsonify(result='saved', uuid=uuid)
            if action == spec.get('delete'):
                rows.pop(uuid, None)
                return jsonify(result='deleted')
        return jsonify(error='unexpected endpoint'), 404

    upstream_server = make_server('127.0.0.1', 0, firewall, threaded=True, ssl_context='adhoc')
    upstream_thread = threading.Thread(target=upstream_server.serve_forever, daemon=True)
    upstream_thread.start()
    spec = importlib.util.spec_from_file_location('workspace_e2e_plugin', ROOT / '__init__.py')
    plugin = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(plugin)
    for filename in ('workspace.html', 'workspace.js', 'workspace.css'):
        shutil.copy2(ROOT / filename, tmp_path / filename)
    monkeypatch.setattr(plugin, 'PLUGIN_DIR', str(tmp_path))
    monkeypatch.setattr(plugin, '_load_config', lambda: {'read_only': state.readonly,
        'opnsense_hosts': [{'name': 'simulator', 'url': f'https://127.0.0.1:{upstream_server.server_port}',
            'api_key': 'test-key', 'api_secret': 'test-secret', 'verify_tls': False}]})
    auth = types.ModuleType('pegaprox.utils.auth')
    auth.require_auth = lambda perms: lambda fn: lambda: fn() if state.permitted else ('denied', 403)
    monkeypatch.setitem(sys.modules, 'pegaprox.utils.auth', auth)
    app = Flask('workspace_host')
    @app.before_request
    def capture():
        state.requests.append((request.method, request.path, dict(request.args)))
    for endpoint in ('catalog', 'manage', 'operate', 'workspace', 'workspace_js', 'workspace_css'):
        app.add_url_rule(PREFIX + '/' + endpoint, endpoint=endpoint,
            view_func=getattr(plugin, '_h_' + endpoint), methods=['GET', 'POST'] if endpoint in ('manage', 'operate') else ['GET'])
    @app.get('/favicon.ico')
    def favicon():
        return '', 204
    server = create_server(app, host='127.0.0.1', port=0, threads=4)
    stop = threading.Event()
    def serve():
        try:
            while not stop.is_set():
                server.asyncore.loop(timeout=.1, map=server._map, count=1)
        finally:
            server.task_dispatcher.shutdown()
            for dispatcher in list(server._map.values()):
                dispatcher.close()
    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    state.url = f'http://127.0.0.1:{server.effective_port}{PREFIX}'
    state.catalog_size = len(RESOURCES) + len(OPERATIONS)
    yield state
    stop.set()
    thread.join(10)
    upstream_server.shutdown()
    upstream_thread.join(3)
    assert not thread.is_alive()


@pytest.fixture
def ws_page(ws_browser, ws_stack):
    context = ws_browser.new_context(viewport={'width': 1440, 'height': 1000})
    page = context.new_page()
    errors = []
    page.on('pageerror', lambda error: errors.append(str(error)))
    page.on('dialog', lambda dialog: dialog.accept())
    yield page
    context.close()
    assert errors == []


def open_wireguard(page, stack, theme='corp-dark'):
    from playwright.sync_api import expect
    page.goto(stack.url + '/workspace?theme=' + theme + '#wireguard_servers')
    expect(page.locator('#table-region')).to_have_attribute('aria-busy', 'false')
    expect(page.locator('#new-item')).to_be_enabled()
    return page.locator('#entry-form')


def create_draft(page, stack):
    from playwright.sync_api import expect
    open_wireguard(page, stack)
    page.locator('#new-item').click()
    expect(page.locator('[name=name]')).to_be_visible()
    page.locator('[name=name]').fill('E2E tunnel')
    page.locator('[name=privkey]').fill('test-secret-value')
    page.locator('[name=enabled]').uncheck()


def submit(page):
    with page.expect_response(lambda response: response.url.endswith('/manage') and response.request.method == 'POST') as response:
        page.locator('#save-item').click()
    return response.value


def test_workspace_lazy_catalog_and_real_crud_secret_preservation(ws_page, ws_stack):
    from playwright.sync_api import expect
    page, stack = ws_page, ws_stack
    page.goto(stack.url + '/workspace')
    expect(page.locator('.module-link')).to_have_count(stack.catalog_size)
    assert stack.calls == [], 'catalog must not fan out to upstream modules'
    create_draft(page, stack)
    page.locator('[name=peers]').select_option(['peer-a', 'peer-b'])
    assert submit(page).status == 200
    expect(page.locator('#result-status')).to_contain_text('aplicado y verificado')
    uuid, stored = next(iter(stack.rows['wireguard_servers'].items()))
    assert stored['privkey'] == 'test-secret-value'
    assert stored['enabled'] == '0'
    assert stored['peers'] == 'peer-a,peer-b'
    page.get_by_role('button', name='Ver detalle', exact=True).click()
    expect(page.locator('[name=privkey]')).to_have_value('')
    expect(page.locator('[name=name]')).to_have_value('E2E tunnel')
    page.locator('[name=name]').fill('E2E edited')
    assert submit(page).status == 200
    expect(page.locator('#result-status')).to_be_visible()
    assert stack.rows['wireguard_servers'][uuid]['privkey'] == 'test-secret-value'
    assert 'test-secret-value' not in page.content()
    page.get_by_role('button', name='Ver detalle', exact=True).click()
    expect(page.locator('#delete-item')).to_be_enabled()
    with page.expect_response(lambda response: response.url.endswith('/manage') and response.request.method == 'POST') as response:
        page.locator('#delete-item').click()
    assert response.value.status == 200
    expect(page.locator('#result-status')).to_be_visible()
    expect(page.locator('#table-region')).to_have_attribute('aria-busy', 'false')
    assert stack.rows['wireguard_servers'] == {}


@pytest.mark.parametrize('failure', ['reject_save', 'reject_apply'])
def test_workspace_failure_retains_draft_and_partial_blocks_retries(ws_page, ws_stack, failure):
    from playwright.sync_api import expect
    page, stack = ws_page, ws_stack
    create_draft(page, stack)
    setattr(stack, failure, True)
    response = submit(page)
    assert response.status >= 400
    expect(page.locator('#editor-error')).to_be_visible()
    expect(page.locator('[name=name]')).to_have_value('E2E tunnel')
    expect(page.locator('[name=privkey]')).to_have_value('')
    if failure == 'reject_apply':
        expect(page.locator('#save-item')).to_be_disabled()
        assert len(stack.rows['wireguard_servers']) == 1
        writes = [call for call in stack.calls if call[0] == 'POST']
        page.locator('#refresh-list').click()
        expect(page.locator('#table-region')).to_have_attribute('aria-busy', 'false')
        expect(page.locator('#save-item')).to_be_disabled()
        page.locator('#entry-form').evaluate('form => form.requestSubmit()')
        assert [call for call in stack.calls if call[0] == 'POST'] == writes
        expect(page.locator('#reconcile')).to_be_visible()


@pytest.mark.parametrize('gate', ['readonly', 'role'])
def test_workspace_readonly_permissions_fail_closed(ws_page, ws_stack, gate):
    from playwright.sync_api import expect
    page, stack = ws_page, ws_stack
    if gate == 'readonly':
        stack.readonly = True
    else:
        stack.permitted = False
    page.goto(stack.url + '/workspace#wireguard_servers')
    expect(page.locator('#resource-access')).to_contain_text('solo lectura')
    expect(page.locator('#new-item')).to_be_disabled()
    before = list(stack.calls)
    response = page.request.post(stack.url + '/manage', data={'resource': 'wireguard_servers', 'action': 'create', 'values': {}})
    assert response.status == 403
    assert stack.calls == before


def test_workspace_unavailable_is_error_not_empty_success(ws_page, ws_stack):
    from playwright.sync_api import expect
    ws_stack.unavailable = True
    ws_page.goto(ws_stack.url + '/workspace#wireguard_servers')
    expect(ws_page.locator('#list-error')).to_be_visible()
    expect(ws_page.locator('#new-item')).to_be_disabled()
    expect(ws_page.locator('#table-body')).to_contain_text('no está disponible')


def test_workspace_pagination_search_and_shaper_defaults(ws_page, ws_stack):
    from playwright.sync_api import expect
    page, stack = ws_page, ws_stack
    for index in range(51):
        stack.rows['shaper_pipes'][str(uuid4())] = {'enabled': '0', 'bandwidth': '10',
            'bandwidthMetric': 'Mbit', 'description': f'pipe-{index:02d}'}
    page.goto(stack.url + '/workspace#shaper_pipes')
    expect(page.locator('#list-count')).to_contain_text('51 entradas')
    assert len(stack.calls) == 1, 'list must not fetch details per row'
    expect(page.locator('#table-body tr')).to_have_count(50)
    page.locator('#next-page').click()
    expect(page.locator('#page-number')).to_have_text('2')
    expect(page.locator('#table-body tr')).to_have_count(1)
    page.locator('#list-search').fill('pipe-20')
    page.locator('#list-search-form button').click()
    expect(page.locator('#list-count')).to_contain_text('1 entradas')
    expect(page.locator('#table-body')).to_contain_text('pipe-20')
    page.locator('#new-item').click()
    expect(page.locator('[name=bandwidthMetric]')).to_have_value('Kbit')
    page.locator('[name=bandwidth]').fill('25')
    page.locator('[name=description]').fill('E2E shaping')
    response = submit(page)
    assert response.status == 200, response.text()
    expect(page.locator('#result-status')).to_be_visible()
    assert any(row['description'] == 'E2E shaping' for row in stack.rows['shaper_pipes'].values())


def test_workspace_operation_get_and_readonly_post_denied(ws_page, ws_stack):
    from playwright.sync_api import expect
    page, stack = ws_page, ws_stack
    stack.readonly = True
    page.goto(stack.url + '/workspace#wireguard_status')
    expect(page.locator('#operation-result')).to_contain_text('running')
    assert all(call[0] == 'GET' for call in stack.calls)
    page.locator('[data-resource=firmware_check]').click()
    expect(page.locator('#save-item')).to_be_disabled()
    before = list(stack.calls)
    response = page.request.post(stack.url + '/operate', data={'operation': 'firmware_check', 'values': {}})
    assert response.status == 403
    assert stack.calls == before


def test_workspace_singleton_only_updates_settings(ws_page, ws_stack):
    from playwright.sync_api import expect
    page = ws_page
    page.goto(ws_stack.url + '/workspace#wireguard_general')
    expect(page.locator('#list-count')).to_contain_text('1 entradas')
    expect(page.locator('#new-item')).to_be_hidden()
    page.get_by_role('button', name='Ver detalle', exact=True).click()
    expect(page.locator('#delete-item')).to_be_hidden()
    expect(page.locator('[name=enabled]')).not_to_be_checked()
    page.locator('[name=enabled]').check()
    response = submit(page)
    assert response.status == 200, response.text()
    expect(page.locator('#result-status')).to_be_visible()
    expect(page.locator('#table-region')).to_have_attribute('aria-busy', 'false')
    assert ws_stack.rows['wireguard_general']['settings']['enabled'] == '1'


def test_workspace_stale_detail_blocks_overwrite(ws_page, ws_stack):
    from playwright.sync_api import expect
    page, stack = ws_page, ws_stack
    create_draft(page, stack)
    assert submit(page).status == 200
    expect(page.locator('#result-status')).to_be_visible()
    page.get_by_role('button', name='Ver detalle', exact=True).click()
    expect(page.locator('[name=name]')).to_have_value('E2E tunnel')
    uuid = next(iter(stack.rows['wireguard_servers']))
    stack.rows['wireguard_servers'][uuid]['name'] = 'Another administrator changed this'
    page.locator('[name=name]').fill('Old browser draft')
    before = [call for call in stack.calls if call[0] == 'POST']
    assert submit(page).status == 409
    expect(page.locator('#editor-error')).to_be_visible()
    expect(page.locator('[name=name]')).to_have_value('Old browser draft')
    assert [call for call in stack.calls if call[0] == 'POST'] == before
    assert stack.rows['wireguard_servers'][uuid]['name'] == 'Another administrator changed this'


def test_workspace_accepted_operation_never_claims_verified(ws_page, ws_stack):
    from playwright.sync_api import expect
    page, stack = ws_page, ws_stack
    page.goto(stack.url + '/workspace#firmware_check')
    expect(page.locator('#save-item')).to_be_enabled()
    assert stack.calls == [], 'opening an operation must never execute POST'
    with page.expect_response(lambda response: response.url.endswith('/operate')) as response:
        page.locator('#save-item').click()
    assert response.value.status == 200
    expect(page.locator('#reconcile-warning')).to_contain_text('pendiente de verificar')
    expect(page.locator('#result-status')).to_be_hidden()
    expect(page.locator('#save-item')).to_be_disabled()
    assert len([call for call in stack.calls if call[0] == 'POST']) == 1


@pytest.mark.parametrize('theme', ['corp-dark', 'corp-light', 'cloud'])
def test_workspace_mobile_themes_and_sidebar_search(ws_page, ws_stack, theme):
    from playwright.sync_api import expect
    page = ws_page
    page.set_viewport_size({'width': 390, 'height': 844})
    open_wireguard(page, ws_stack, theme)
    page.locator('#module-search').fill('WireGuard')
    from src.management.catalog import RESOURCES
    from src.management.operations import OPERATIONS
    count = sum('wireguard' in f"{spec['id']} {spec['label']} {spec['group']}".lower() for spec in [*RESOURCES.values(), *OPERATIONS.values()])
    expect(page.locator('.module-link')).to_have_count(count)
    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
    page.locator('#new-item').click()
    expect(page.locator('[name=name]')).to_be_visible()
    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
    directory = os.getenv('E2E_ARTIFACT_DIR')
    if directory:
        Path(directory).mkdir(parents=True, exist_ok=True)
        page.screenshot(path=str(Path(directory) / f'workspace-mobile-{theme}.png'), full_page=True, animations='disabled')
