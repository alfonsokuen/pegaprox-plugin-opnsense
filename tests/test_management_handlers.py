"""Authorization and dispatch at the actual host plugin boundary."""
import importlib.util
from pathlib import Path

from flask import Flask
import pytest


@pytest.fixture
def plugin(monkeypatch):
    spec = importlib.util.spec_from_file_location('management_handler_test', Path(__file__).parents[1] / '__init__.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, '_load_config', lambda: {'opnsense_hosts': [], 'read_only': True})
    monkeypatch.setattr(module, '_firewall_can_write', lambda: False)
    return module


def test_catalog_is_readonly_and_does_not_probe_upstream(plugin, monkeypatch):
    monkeypatch.setattr(plugin, '_firewall_target', lambda *a, **k: pytest.fail('catalog must not query devices'))
    with Flask(__name__).test_request_context('/catalog'):
        response = plugin._h_catalog()
    assert response.json['ok']
    assert response.json['data']['read_only'] is True
    assert response.json['data']['resources']


def test_unknown_resource_rejected_before_upstream(plugin, monkeypatch):
    monkeypatch.setattr(plugin, '_firewall_target', lambda *a, **k: pytest.fail('unknown resource queried device'))
    with Flask(__name__).test_request_context('/manage?resource=../../system/reboot'):
        response, status = plugin._h_manage()
    assert status == 404 and response.json['error'] == 'unknown_resource'


@pytest.mark.parametrize('readonly,permission,error', [(True, True, 'read_only'), (False, False, 'forbidden')])
def test_write_permissions_block_before_upstream(plugin, monkeypatch, readonly, permission, error):
    from src.management.catalog import RESOURCES
    resource = next(iter(RESOURCES))
    monkeypatch.setattr(plugin, '_load_config', lambda: {'read_only': readonly, 'opnsense_hosts': []})
    monkeypatch.setattr(plugin, '_firewall_can_write', lambda: permission)
    monkeypatch.setattr(plugin, '_firewall_target', lambda *a, **k: pytest.fail('denied write queried device'))
    with Flask(__name__).test_request_context('/manage', method='POST', json={'resource': resource, 'action': 'create', 'values': {}}):
        response, status = plugin._h_manage()
    assert status == 403 and response.json['error'] == error


def test_workspace_assets_are_fixed_and_not_writable(plugin):
    app = Flask(__name__)
    with app.test_request_context('/workspace', method='POST'):
        _, status = plugin._h_workspace()
    assert status == 405


def test_register_includes_workspace_and_management(plugin, monkeypatch):
    seen = {}
    monkeypatch.setattr(plugin, 'register_plugin_route', lambda identity, path, handler: seen.update({path: handler}))
    plugin.register()
    assert {'catalog', 'manage', 'workspace', 'workspace_js', 'workspace_css'} <= set(seen)


def test_operate_rejects_unknown_id_without_probe(plugin, monkeypatch):
    monkeypatch.setattr(plugin, '_firewall_target', lambda *a, **k: pytest.fail('unknown operation queried device'))
    with Flask(__name__).test_request_context('/operate?operation=https://evil.test'):
        response, status = plugin._h_operate()
    assert status == 404 and response.json['error'] == 'unknown_operation'


def test_get_cannot_trigger_post_operation(plugin, monkeypatch):
    from src.management.operations import OPERATIONS
    operation = next(key for key, spec in OPERATIONS.items() if spec['method'] == 'POST')
    monkeypatch.setattr(plugin, '_firewall_target', lambda *a, **k: pytest.fail('GET triggered action'))
    with Flask(__name__).test_request_context('/operate?operation=' + operation):
        response, status = plugin._h_operate()
    assert status == 405 and response.json['error'] == 'method_not_allowed'


def test_operation_readonly_blocks_post_before_probe(plugin, monkeypatch):
    from src.management.operations import OPERATIONS
    operation = next(key for key, spec in OPERATIONS.items() if spec['method'] == 'POST')
    monkeypatch.setattr(plugin, '_firewall_target', lambda *a, **k: pytest.fail('readonly triggered action'))
    with Flask(__name__).test_request_context('/operate', method='POST', json={'operation': operation, 'values': {}}):
        response, status = plugin._h_operate()
    assert status == 403 and response.json['error'] == 'read_only'


@pytest.mark.parametrize('method', ['GET', 'POST'])
def test_backups_require_admin_even_for_download(plugin, monkeypatch, method):
    monkeypatch.setattr(plugin, '_firewall_target', lambda *a, **k: pytest.fail('unauthorized backup probed device'))
    with Flask(__name__).test_request_context('/backups?download=1&id=x', method=method, json={'action': 'create'}):
        response, status = plugin._h_backups()
    assert status == 403 and response.json['error'] == 'forbidden'


def test_backup_list_does_not_contact_firewall(plugin, monkeypatch, tmp_path):
    monkeypatch.setattr(plugin, '_firewall_can_write', lambda: True)
    monkeypatch.setattr(plugin, 'STATE_DIR', str(tmp_path))
    monkeypatch.setattr(plugin, '_firewall_target', lambda *a, **k: pytest.fail('local list probed device'))
    with Flask(__name__).test_request_context('/backups'):
        response, status = plugin._h_backups()
    assert status == 200 and response.json['data']['items'] == []
