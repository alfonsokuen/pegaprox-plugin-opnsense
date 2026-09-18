"""Exercise registered handlers, configuration gates and HA target selection."""
import importlib.util
import json
import pathlib
import sys
import types

import pytest
from flask import Flask


@pytest.fixture
def plugin(monkeypatch):
    path = pathlib.Path(__file__).parents[1] / '__init__.py'
    spec = importlib.util.spec_from_file_location('firewall_entry_test', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module._real_firewall_can_write = module._firewall_can_write
    monkeypatch.setattr(module, '_firewall_can_write', lambda: True)
    return module


def config(read_only=False, cluster=False):
    hosts = [{'name': 'A', 'url': 'https://a.test', 'api_key': 'test', 'api_secret': 'test'}]
    if cluster:
        hosts.append({**hosts[0], 'name': 'B', 'url': 'https://b.test'})
    return {'opnsense_hosts': hosts, 'read_only': read_only, 'cluster_mode': 'auto'}


def test_read_only_blocks_before_any_firewall_probe(plugin, monkeypatch):
    monkeypatch.setattr(plugin, '_load_config', lambda: config(read_only=True))
    with Flask(__name__).test_request_context(method='POST', json={'action': 'create'}):
        response, status = plugin._h_port_forward()
    assert status == 403
    assert response.json['error'] == 'read_only'


@pytest.mark.parametrize('body', [[], 'text', None])
def test_non_object_json_is_rejected(plugin, monkeypatch, body):
    monkeypatch.setattr(plugin, '_load_config', lambda: config())
    with Flask(__name__).test_request_context(method='POST', json=body):
        response, status = plugin._h_rules()
    assert status == 400
    assert response.json['error'] == 'bad_request'


def carp(role, statuses=None):
    return {'role': role, 'enabled': True, 'maintenance_mode': False,
            'vhids': [{'vhid': str(i), 'ipaddr': f'192.0.2.{i}', 'status': s}
                      for i, s in enumerate(statuses or [role.upper()], 1)]}


@pytest.mark.parametrize('left,right', [
    (carp('master'), carp('master')),
    (carp('backup'), carp('backup')),
    (carp('master'), carp('unknown')),
    (carp('master', ['MASTER', 'BACKUP']), carp('backup', ['BACKUP', 'MASTER'])),
])
def test_ambiguous_ha_refuses_writes(plugin, monkeypatch, left, right):
    from src.collectors import carp as collector
    monkeypatch.setattr(plugin, '_load_config', lambda: config(cluster=True))
    monkeypatch.setattr(collector, 'collect_carp_status', lambda c: left if c.host.name == 'A' else right)
    with Flask(__name__).test_request_context(method='POST', json={'action': 'create'}):
        response, status = plugin._h_aliases()
    assert status == 409
    assert response.json['error'] == 'ha_unsafe'


def test_confirmed_master_receives_write_and_peer_is_passed(plugin, monkeypatch):
    from src.collectors import carp as collector
    monkeypatch.setattr(plugin, '_load_config', lambda: config(cluster=True))
    monkeypatch.setattr(collector, 'collect_carp_status',
                        lambda c: carp('backup' if c.host.name == 'A' else 'master'))
    calls = []
    fake = types.ModuleType('src.routes.firewall')
    def action(host, plugin_dir, body, **kwargs):
        calls.append((host, kwargs))
        return 200, {'ok': True, 'data': {'uuid': 'test'}}
    fake.build_firewall_action_payload = action
    fake.build_firewall_list_payload = lambda *a, **k: (200, {'ok': True, 'data': {'rules': []}})
    monkeypatch.setitem(sys.modules, 'src.routes.firewall', fake)
    with Flask(__name__).test_request_context(method='POST', json={'action': 'create'}):
        _, status = plugin._h_port_forward()
    assert status == 200
    assert calls[0][0].name == 'B'
    assert calls[0][1]['peer_host'].name == 'A'


def test_list_exposes_read_only_without_credentials(plugin, monkeypatch):
    monkeypatch.setattr(plugin, '_load_config', lambda: config(read_only=True))
    fake = types.ModuleType('src.routes.firewall')
    fake.build_firewall_list_payload = lambda *a, **k: (200, {'ok': True, 'data': {'rules': []}})
    fake.build_firewall_action_payload = None
    monkeypatch.setitem(sys.modules, 'src.routes.firewall', fake)
    with Flask(__name__).test_request_context(method='GET'):
        response, status = plugin._h_port_forward()
    assert status == 200
    assert response.json['data']['read_only'] is True
    assert 'api_secret' not in response.get_data(as_text=True)


def test_view_only_user_cannot_write(plugin, monkeypatch):
    monkeypatch.setattr(plugin, '_load_config', lambda: config())
    monkeypatch.setattr(plugin, '_firewall_can_write', lambda: False)
    with Flask(__name__).test_request_context(method='POST', json={'action': 'delete'}):
        response, status = plugin._h_rules()
    assert status == 403
    assert response.json['error'] == 'forbidden'


@pytest.mark.parametrize('raw', ['{}', '{"read_only":"false"}', '[]', 'invalid'])
def test_missing_or_invalid_readonly_fails_closed(plugin, monkeypatch, tmp_path, raw):
    path = tmp_path / 'config.json'
    path.write_text(raw)
    monkeypatch.setattr(plugin, 'CONFIG_PATH', str(path))
    assert plugin._load_config()['read_only'] is True


def test_health_version_matches_manifest(plugin):
    manifest = json.loads((pathlib.Path(plugin.PLUGIN_DIR) / 'manifest.json').read_text(encoding='utf-8'))
    assert plugin._h_health()['version'] == plugin.PLUGIN_VERSION == manifest['version']


def test_actor_comes_from_pegaprox_session(plugin, monkeypatch):
    monkeypatch.setattr(plugin, '_load_config', lambda: config())
    calls = []
    fake = types.ModuleType('src.routes.firewall')
    def action(*args, **kwargs):
        calls.append(kwargs)
        return 200, {'ok': True}
    fake.build_firewall_action_payload = action
    fake.build_firewall_list_payload = None
    monkeypatch.setitem(sys.modules, 'src.routes.firewall', fake)
    from flask import request
    with Flask(__name__).test_request_context(method='POST', json={'action': 'create'},
                                             headers={'X-User': 'forged-user'}):
        request.session = {'user': 'authenticated-user'}
        _, status = plugin._h_rules()
    assert status == 200
    assert calls[0]['actor'] == 'authenticated-user'


LEGACY = [
    ('nat', 'nat'), ('unbound', 'unbound'), ('dhcp', 'dhcp'),
    ('dhcp_subnet', 'dhcp_subnet'), ('one_to_one', 'one_to_one'),
    ('unbound_domains', 'unbound_domain'), ('unbound_dots', 'unbound_dot'), ('wg', 'wg'),
]
ALL_MANAGED = [name for name, _ in LEGACY] + ['rules', 'aliases', 'port_forward']


@pytest.mark.parametrize('handler', ALL_MANAGED)
@pytest.mark.parametrize('readonly,allowed,error', [(True, True, 'read_only'), (False, False, 'forbidden')])
def test_every_write_gate_denies_before_any_target_probe(plugin, monkeypatch, handler, readonly, allowed, error):
    monkeypatch.setattr(plugin, '_load_config', lambda: config(read_only=readonly, cluster=True))
    monkeypatch.setattr(plugin, '_firewall_can_write', lambda: allowed)
    monkeypatch.setattr(plugin, '_firewall_target', lambda *a, **k: pytest.fail('Denied writes must not probe hosts'))
    monkeypatch.setattr(plugin, '_first_host_from_config', lambda: pytest.fail('No unsafe legacy target resolution'))
    with Flask(__name__).test_request_context(method='POST', json={'action': 'create'}):
        response, status = getattr(plugin, '_h_' + handler)()
    assert status == 403 and response.json['error'] == error


@pytest.mark.parametrize('handler,builder', LEGACY)
def test_legacy_write_uses_fresh_master_actor_and_single_snapshot(plugin, monkeypatch, handler, builder):
    from flask import request

    import src.routes
    from src.collectors import carp as collector

    snapshots = []
    def load_once():
        snapshots.append(True)
        assert len(snapshots) == 1, 'A write must use a single configuration snapshot'
        return config(cluster=True)
    monkeypatch.setattr(plugin, '_load_config', load_once)
    # Deliberately stale read cache points at A; the live master is B.
    monkeypatch.setattr(plugin, '_resolved_master_side', lambda *a, **k: pytest.fail('Writes must bypass cached primary'))
    probes = []
    def collect(client):
        probes.append(client.host.name)
        return carp('backup' if client.host.name == 'A' else 'master')
    monkeypatch.setattr(collector, 'collect_carp_status', collect)
    calls = []
    def action(host, plugin_dir, body, **kwargs):
        calls.append((host.name, plugin_dir, body, kwargs))
        return 200, {'ok': True, 'legacy_shape': 'preserved'}
    monkeypatch.setattr(src.routes, f'build_{builder}_action_payload', action)
    with Flask(__name__).test_request_context(method='POST', json={'action': 'create'}, headers={'X-User': 'forged'}):
        request.session = {'user': 'real-operator'}
        response, status = getattr(plugin, '_h_' + handler)()
    assert status == 200 and response.json['legacy_shape'] == 'preserved'
    assert probes == ['A', 'B'] and len(snapshots) == 1
    assert calls == [('B', plugin.PLUGIN_DIR, {'action': 'create'}, {'actor': 'real-operator', 'read_only': False})]


@pytest.mark.parametrize('handler', ALL_MANAGED)
def test_network_error_at_target_gate_is_safe_json(plugin, monkeypatch, handler):
    from src.client import OPNsenseTimeoutError
    from src.collectors import carp as collector

    monkeypatch.setattr(plugin, '_load_config', lambda: config(cluster=True))
    def unavailable(client):
        raise OPNsenseTimeoutError('HA probe timed out')
    monkeypatch.setattr(collector, 'collect_carp_status', unavailable)
    with Flask(__name__).test_request_context(method='POST', json={'action': 'create'}):
        response, status = getattr(plugin, '_h_' + handler)()
    assert status == 502 and response.json['error'] == 'ha_unavailable'


@pytest.mark.parametrize('handler', ALL_MANAGED)
@pytest.mark.parametrize('method', ['PUT', 'DELETE', 'PATCH'])
def test_management_only_accepts_get_and_post(plugin, monkeypatch, handler, method):
    monkeypatch.setattr(plugin, '_load_config', lambda: config())
    monkeypatch.setattr(plugin, '_firewall_target', lambda *a, **k: pytest.fail('Unsupported method must not probe hosts'))
    with Flask(__name__).test_request_context(method=method, json={'action': 'create'}):
        response, status = getattr(plugin, '_h_' + handler)()
    assert status == 405 and response.json['error'] == 'method_not_allowed'


@pytest.mark.parametrize('handler,builder', LEGACY)
def test_legacy_read_remains_available_to_viewer(plugin, monkeypatch, handler, builder):
    import src.routes

    monkeypatch.setattr(plugin, '_load_config', lambda: config(read_only=True))
    monkeypatch.setattr(plugin, '_firewall_can_write', lambda: False)
    monkeypatch.setattr(src.routes, f'build_{builder}_list_payload',
                        lambda host: (200, {'ok': True, 'host': host.name, 'legacy': True, 'data': {}}))
    with Flask(__name__).test_request_context(method='GET'):
        response, status = getattr(plugin, '_h_' + handler)()
    assert status == 200 and response.json == {'ok': True, 'host': 'A', 'legacy': True, 'data': {'read_only': True}}


def test_permission_resolver_abort_fails_closed(plugin, monkeypatch):
    from flask import abort

    fake = types.ModuleType('pegaprox.utils.auth')
    def require_auth(perms):
        assert perms == ['plugins.manage']
        def decorate(handler):
            def denied():
                abort(403)
            return denied
        return decorate
    fake.require_auth = require_auth
    monkeypatch.setitem(sys.modules, 'pegaprox.utils.auth', fake)
    with Flask(__name__).test_request_context():
        assert plugin._real_firewall_can_write() is False


@pytest.mark.parametrize('handler', ALL_MANAGED)
def test_actual_carp_collector_timeout_is_already_fail_closed(plugin, monkeypatch, handler):
    from src.client import OPNsenseClient, OPNsenseTimeoutError

    monkeypatch.setattr(plugin, '_load_config', lambda: config(cluster=True))
    def unavailable(self, path, **params):
        raise OPNsenseTimeoutError('real client timeout')
    monkeypatch.setattr(OPNsenseClient, 'get', unavailable)
    monkeypatch.setattr(OPNsenseClient, 'post', lambda *a, **k: pytest.fail('No mutation after failed CARP reads'))
    with Flask(__name__).test_request_context(method='POST', json={'action': 'create'}):
        response, status = getattr(plugin, '_h_' + handler)()
    # collect_carp_status._safe_get converts OPNsenseError to an empty snapshot;
    # the target gate rejects missing enabled VIPs. The new exception catcher
    # is defensive for other/upcoming collector behavior, not a prior bypass.
    assert status == 409 and response.json['error'] == 'ha_unsafe'
