import json

import pytest
import requests
import responses

from src.client import OPNsenseClient, OPNsenseHost
from src.management.crl import CrlService
from src.management.engine import ManagementError
from src.writers.audit import AuditLog

BASE = 'https://crl.test/api/trust/crl/'
CA = '123456789abcd'
CERT = 'abcdef1234567'


def raw(descr='Current', serial='1', revoked=None):
    result = dict(caref=CA, descr=descr, serial=serial, lifetime='9999',
                  crlmethod={'internal': {'value': 'Internal', 'selected': '1'},
                             'existing': {'value': 'Existing', 'selected': '0'}}, text='')
    for number in range(7):
        result[f'revoked_reason_{number}'] = {CERT: {'value': 'Certificate',
            'selected': '1' if revoked == number else '0'}}
    return {'crl': result}


@pytest.fixture
def service(tmp_path):
    client = OPNsenseClient(OPNsenseHost('lab', 'https://crl.test', 'key', 'secret'))
    yield CrlService(client, AuditLog(str(tmp_path / 'audit.jsonl')), 'qa')
    client.close()


def detail(service, body=None):
    responses.get(BASE + 'get/' + CA, json=body or raw())
    return service.detail(CA)


@responses.activate
def test_create_addresses_ca_refid_and_verifies_auto_increment(service):
    current = detail(service, raw('', '0'))
    responses.get(BASE + 'get/' + CA, json=raw('', '0'))
    responses.post(BASE + 'set/' + CA, json={'status': 'saved'})
    responses.get(BASE + 'get/' + CA, json=raw('New', '1'))
    result = service.mutate(dict(action='create', uuid=CA, revision=current['revision'], values={'descr': 'New'}))
    assert result['config_saved'] and result['verified'] and result['applied'] is False
    sent = json.loads([call for call in responses.calls if call.request.method == 'POST'][0].request.body)
    assert sent['crl']['caref'] == CA and sent['crl']['serial'] == '0'


@responses.activate
def test_revoke_preserves_other_configuration_and_exact_reason(service):
    current = detail(service)
    responses.get(BASE + 'get/' + CA, json=raw())
    responses.post(BASE + 'set/' + CA, json={'status': 'saved'})
    responses.get(BASE + 'get/' + CA, json=raw(serial='2', revoked=1))
    result = service.mutate(dict(action='revoke', uuid=CA, revision=current['revision'],
                                values={'certificate': CERT, 'reason': '1'}))
    assert result['verified']
    sent = json.loads([call for call in responses.calls if call.request.method == 'POST'][0].request.body)['crl']
    assert sent['revoked_reason_1'] == CERT and sent['revoked_reason_0'] == ''
    assert sent['descr'] == 'Current'


@responses.activate
def test_delete_reads_defaults_not_missing_ca(service):
    current = detail(service)
    responses.get(BASE + 'get/' + CA, json=raw())
    responses.post(BASE + 'del/' + CA, json={'status': 'deleted'})
    responses.get(BASE + 'get/' + CA, json=raw('', '0'))
    assert service.mutate(dict(action='delete', uuid=CA, revision=current['revision']))['verified']


@responses.activate
def test_stale_revision_never_posts(service):
    detail(service)
    with pytest.raises(ManagementError) as error:
        service.mutate(dict(action='delete', uuid=CA, revision='0' * 64))
    assert error.value.error == 'conflict'
    assert all(call.request.method == 'GET' for call in responses.calls)


@pytest.mark.parametrize('values', [
    {'revoked_reason_0': ['fffffffffffff']}, {'revoked_reason_0': [CERT], 'revoked_reason_1': [CERT]},
    {'lifetime': 0}, {'lifetime': True}, {'prv': 'SECRET'}, {'serial': '999'},
    {'crlmethod': 'existing', 'text': '-----BEGIN PRIVATE KEY-----SECRET'},
])
@responses.activate
def test_invalid_mutations_never_post_or_expose_sensitive_input(service, values):
    current = detail(service)
    with pytest.raises(ManagementError) as error:
        service.mutate(dict(action='update', uuid=CA, revision=current['revision'], values=values))
    assert 'SECRET' not in str(error.value)
    assert all(call.request.method == 'GET' for call in responses.calls)


@responses.activate
def test_upstream_validation_is_sanitized(service):
    current = detail(service)
    responses.post(BASE + 'set/' + CA, json={'status': 'failed', 'validations': {'crl.text': 'SECRET'}})
    with pytest.raises(ManagementError) as error:
        service.mutate(dict(action='update', uuid=CA, revision=current['revision'], values={'descr': 'New'}))
    assert error.value.error == 'validation' and not error.value.partial
    assert 'SECRET' not in str(error.value)


@responses.activate
def test_readback_mismatch_and_timeout_are_explicit_partial(service):
    current = detail(service)
    responses.post(BASE + 'set/' + CA, body=requests.Timeout('SECRET'))
    with pytest.raises(ManagementError) as error:
        service.mutate(dict(action='update', uuid=CA, revision=current['revision'], values={'descr': 'New'}))
    assert error.value.partial
    assert sum(call.request.method == 'POST' for call in responses.calls) == 1


@responses.activate
def test_unexpected_secret_keys_are_not_exposed(service):
    response = raw()
    response['crl'].update(prv='SECRET', password='SECRET', unexpected={'secret': 'SECRET'})
    assert 'SECRET' not in json.dumps(detail(service, response))


@responses.activate
def test_empty_php_arrays_are_valid_empty_revocation_options(service):
    response = raw()
    for number in range(7):
        response['crl'][f'revoked_reason_{number}'] = []
    assert detail(service, response)['item']['revoked_reason_0'] == ''


@responses.activate
def test_list_is_ca_inventory_even_when_no_crl_exists(service):
    responses.get(BASE + 'search', json={'rows': [{'refid': CA, 'descr': 'CA', 'prv': 'SECRET'}], 'total': 1})
    result = service.list()
    assert result['rows'] == [{'uuid': CA, 'refid': CA, 'descr': 'CA'}]


@responses.activate
def test_uuid_and_path_injection_are_not_accepted_as_refid(service):
    for value in ('../x', '12345678-1234-1234-1234-123456789abc', None):
        with pytest.raises(ManagementError):
            service.detail(value)
    assert not responses.calls


@responses.activate
def test_ha_not_qualified_never_requests(service):
    service.peer = service.client
    with pytest.raises(ManagementError) as error:
        service.mutate(dict(action='delete', uuid=CA, revision='0' * 64))
    assert error.value.error == 'ha_unqualified' and not responses.calls
