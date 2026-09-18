import json

import pytest
import requests
import responses

from src.client import OPNsenseClient, OPNsenseHost
from src.management.engine import ManagementError
from src.management.operations import OPERATIONS, execute_operation
from src.writers.audit import AuditLog

BASE = 'https://operations.test'
UUID = '11111111-1111-4111-8111-111111111111'


@pytest.fixture
def context(tmp_path):
    client = OPNsenseClient(OPNsenseHost('lab', BASE, 'key', 'secret'))
    log = tmp_path / 'audit.jsonl'
    yield client, AuditLog(str(log)), log
    client.close()


def execute(context, operation, values=None):
    return execute_operation(context[0], context[1], 'qa', operation, values or {})


@responses.activate
def test_service_start_requires_actual_running_readback(context):
    responses.post(BASE + '/api/wireguard/service/start', json={'response': 'OK'})
    responses.get(BASE + '/api/wireguard/service/status', json={'status': 'running'})
    result = execute(context, 'wireguard_start')
    assert result['verified'] and result['state'] == 'running'
    entries = [json.loads(line) for line in context[2].read_text().splitlines()]
    assert [entry['result'] for entry in entries] == ['attempt', 'ok']
    assert len(responses.calls) == 2


@responses.activate
def test_service_wrong_state_is_partial_not_success(context):
    responses.post(BASE + '/api/ids/service/start', json={'response': 'OK'})
    responses.get(BASE + '/api/ids/service/status', json={'status': 'stopped'})
    with pytest.raises(ManagementError) as error:
        execute(context, 'ids_start')
    assert error.value.partial and error.value.error == 'verification'
    assert len(responses.calls) == 2


@responses.activate
def test_async_upgrade_is_only_accepted(context):
    responses.post(BASE + '/api/core/firmware/upgrade', json={'status': 'ok', 'msg_uuid': UUID})
    result = execute(context, 'firmware_upgrade')
    assert result['accepted'] and result['verified'] is False and result['state'] == 'accepted'
    assert 'applied' not in result


@pytest.mark.parametrize('body', [{'status': 'failed'}, {'result': 'error'}, {},
                                 {'status': 'ok', 'validations': {'field': 'SECRET'}}])
@responses.activate
def test_http200_rejection_does_not_pass(context, body):
    responses.post(BASE + '/api/core/firmware/upgrade', json=body)
    with pytest.raises(ManagementError) as error:
        execute(context, 'firmware_upgrade')
    assert 'SECRET' not in str(error.value)
    assert len(responses.calls) == 1


@responses.activate
def test_timeout_post_is_never_retried_and_is_uncertain(context):
    responses.post(BASE + '/api/core/firmware/reboot', body=requests.Timeout('SECRET'))
    with pytest.raises(ManagementError) as error:
        execute(context, 'firmware_reboot')
    assert error.value.partial and error.value.error == 'timeout'
    assert 'SECRET' not in str(error.value)
    assert len(responses.calls) == 1


@responses.activate
def test_response_recursively_excludes_credentials(context):
    responses.get(BASE + '/api/core/firmware/info', json={
        'version': '26.1.2', 'password': 'SECRET', 'rows': [
            {'private_key': 'SECRET', 'api_key': 'SECRET', 'public_key': 'public',
             'nested': {'token': 'SECRET'}, 'url': 'https://user:SECRET@example.test'}]})
    result = execute(context, 'firmware_info')
    assert 'SECRET' not in json.dumps(result)
    assert result['result']['rows'][0]['public_key'] == 'public'


@pytest.mark.parametrize('operation,values', [
    ('https://other.test', {}), ('wireguard_start', {'path': '/api/other'}),
    ('ping_start', {'jobid': '../../reboot'}), ('ipsec_connect', {'id': 'x/../../'}),
    ('reverse_dns', {'address': 'example.com'}), ('traceroute', {'hostname': 'x; reboot'}),
    ('states', {'rowCount': 10000}), ('ping_create', {'hostname': 'x', 'interval': True}),
])
@responses.activate
def test_invalid_values_never_touch_network(context, operation, values):
    with pytest.raises(ManagementError):
        execute(context, operation, values)
    assert not responses.calls


@responses.activate
def test_ping_job_posts_native_nested_model_then_explicit_uuid_start(context):
    responses.post(BASE + '/api/diagnostics/ping/set', json={'result': 'ok', 'uuid': UUID})
    responses.post(BASE + '/api/diagnostics/ping/start/' + UUID, json={'status': 'ok'})
    execute(context, 'ping_create', {'hostname': 'example.test'})
    assert json.loads(responses.calls[0].request.body) == {
        'ping': {'settings': {'hostname': 'example.test', 'fam': 'ip'}}}
    execute(context, 'ping_start', {'jobid': UUID})
    assert json.loads(responses.calls[1].request.body) == {}


@responses.activate
def test_audit_failure_prevents_post(context, monkeypatch):
    def fail(_entry):
        raise OSError('SECRET')
    monkeypatch.setattr(context[1], 'append', fail)
    with pytest.raises(ManagementError) as error:
        execute(context, 'firmware_reboot')
    assert error.value.audit_failure and not error.value.partial
    assert not responses.calls


@responses.activate
def test_monit_real_ack_has_syntax_result_not_generic_ok(context):
    responses.post(BASE + '/api/monit/service/reconfigure', json={
        'status': 'ok', 'function': 'check', 'template': 'OK', 'result': 'Control file syntax OK'})
    assert execute(context, 'monit_reconfigure')['accepted']


@responses.activate
def test_wireguard_reconfigure_returns_result_not_status(context):
    responses.post(BASE + '/api/wireguard/service/reconfigure', json={'result': 'ok'})
    result = execute(context, 'wireguard_reconfigure')
    assert result['accepted'] and result['verified'] is False


@responses.activate
def test_states_is_post_read_without_claiming_mutation(context):
    responses.post(BASE + '/api/diagnostics/firewall/queryStates', json={'rows': [], 'total': 0})
    assert OPERATIONS['states']['mutation'] is False
    assert execute(context, 'states')['state'] == 'observed'


def test_every_disruptive_operation_requires_confirmation_metadata():
    assert all(spec['confirm'] for spec in OPERATIONS.values() if spec['mutation'])
    assert all(spec['path'].startswith('/api/') and '?' not in spec['path'] for spec in OPERATIONS.values())
