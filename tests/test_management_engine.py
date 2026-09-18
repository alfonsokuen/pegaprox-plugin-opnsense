import json

import pytest
import responses

from src.client import OPNsenseClient, OPNsenseHost
from src.management.engine import ManagementError, ManagementService, SINGLETON_UUID, selected
from src.writers.audit import AuditLog, hash_payload

UUID = '11111111-1111-4111-8111-111111111111'
BASE = 'https://engine.test/api/demo/settings'
SPEC = dict(id='demo', base='/api/demo/settings', search='searchItem', get='getItem',
            add='addItem', set='setItem', delete='delItem', key='item',
            apply='/api/demo/service/reconfigure', fields=[
                dict(name='name', kind='text', required=True),
                dict(name='password', kind='text', secret=True),
                dict(name='enabled', kind='boolean'),
                dict(name='nested.port', kind='number')], columns=['name'])


@pytest.fixture
def service(tmp_path):
    client = OPNsenseClient(OPNsenseHost(name='demo', url='https://engine.test', api_key='test', api_secret='test'))
    return ManagementService(client, AuditLog(str(tmp_path / 'audit.jsonl')))


@responses.activate
def test_list_one_call_redacts_unlisted_fields(service):
    responses.get(BASE + '/searchItem', json={'rows': [{'uuid': UUID, 'name': 'a', 'password': 'hidden', 'unknown': 'hidden'}], 'total': 1})
    result = service.list(SPEC)
    assert result['rows'] == [{'uuid': UUID, 'name': 'a'}]
    assert len(responses.calls) == 1


@responses.activate
def test_update_preserves_secret_unknown_and_nested_fields(service):
    current = {'name': 'old', 'password': 'hidden', 'advanced': 'preserved', 'nested': {'port': '80'}}
    responses.get(BASE + '/getItem/' + UUID, json={'item': current})
    responses.post(BASE + '/setItem/' + UUID, json={'result': 'saved'})
    responses.post('https://engine.test/api/demo/service/reconfigure', json={'status': 'ok'})
    responses.get(BASE + '/getItem/' + UUID, json={'item': {**current, 'name': 'new', 'nested': {'port': '443'}}})
    result = service.mutate(SPEC, dict(action='update', uuid=UUID, revision=hash_payload(current),
                                     values={'name': 'new', 'password': '', 'nested.port': 443}))
    assert result['verified'] and result['applied']
    sent = json.loads(responses.calls[1].request.body)['item']
    assert sent['password'] == 'hidden' and sent['advanced'] == 'preserved'
    assert sent['nested']['port'] == '443'


@responses.activate
def test_stale_revision_never_posts(service):
    responses.get(BASE + '/getItem/' + UUID, json={'item': {'name': 'changed'}})
    with pytest.raises(ManagementError) as error:
        service.mutate(SPEC, dict(action='delete', uuid=UUID, revision='0' * 64))
    assert error.value.error == 'conflict'
    assert len(responses.calls) == 1


def test_ha_unqualified_never_requests(service):
    service.peer = service.client
    with pytest.raises(ManagementError) as error:
        service.mutate(SPEC, dict(action='create', values={'name': 'new'}))
    assert error.value.error == 'ha_unqualified'


@responses.activate
def test_detail_redacts_secret_and_exposes_options(service):
    responses.get(BASE + '/getItem/' + UUID, json={'item': {'name': 'a', 'password': 'hidden',
        'enabled': {'1': {'value': 'Yes', 'selected': 1}, '0': {'value': 'No', 'selected': 0}}}})
    result = service.detail(SPEC, UUID)
    assert 'hidden' not in json.dumps(result)
    assert result['item']['password'] == ''
    assert len(result['fields'][2]['options']) == 2


@responses.activate
@pytest.mark.parametrize('failure,expected,partial', [('validation', 'validation', False), ('apply', 'upstream', True), ('readback', 'unverified', True)])
def test_rejected_or_partial_writes_are_explicit(service, failure, expected, partial):
    responses.get(BASE + '/getItem', json={'item': {'name': '', 'enabled': '0'}})
    responses.post(BASE + '/addItem', json={'validations': {'password': 'private upstream text'}} if failure == 'validation' else {'result': 'saved', 'uuid': UUID})
    if failure != 'validation':
        responses.post('https://engine.test/api/demo/service/reconfigure', json={'status': 'failed' if failure == 'apply' else 'ok'})
    if failure == 'readback':
        responses.get(BASE + '/getItem/' + UUID, json={'item': {'name': 'other', 'enabled': '0'}})
    with pytest.raises(ManagementError) as error:
        service.mutate(SPEC, dict(action='create', values={'name': 'new'}))
    assert error.value.error == expected and error.value.partial == partial
    if failure == 'validation':
        assert error.value.validations == {'password': 'Valor rechazado por OPNsense'}
        assert error.value.uuid is None
    else:
        assert error.value.uuid == UUID
    assert 'private upstream text' not in json.dumps(error.value.as_dict())
    assert sum(call.request.method == 'POST' and '/addItem' in call.request.url for call in responses.calls) == 1


@responses.activate
def test_upstream_error_does_not_disclose_raw_body(service):
    responses.get(BASE + '/getItem', body='private response contents', status=400)
    with pytest.raises(ManagementError) as error:
        service.detail(SPEC)
    assert 'private response contents' not in str(error.value)


@responses.activate
def test_audit_failure_prevents_post(service, monkeypatch):
    responses.get(BASE + '/getItem', json={'item': {'name': ''}})
    def fail(entry):
        raise OSError('disk')
    monkeypatch.setattr(service.audit, 'append', fail)
    with pytest.raises(ManagementError) as error:
        service.mutate(SPEC, dict(action='create', values={'name': 'new'}))
    assert error.value.error == 'audit'
    assert all(call.request.method == 'GET' for call in responses.calls)


@responses.activate
def test_missing_apply_refuses_before_contact(service):
    with pytest.raises(ManagementError) as error:
        service.mutate({**SPEC, 'apply': None}, dict(action='create', values={'name': 'new'}))
    assert error.value.error == 'unsupported' and not responses.calls


@responses.activate
def test_unknown_input_cannot_override_hidden_values(service):
    responses.get(BASE + '/getItem', json={'item': {'name': ''}})
    with pytest.raises(ManagementError) as error:
        service.mutate(SPEC, dict(action='create', values={'name': 'new', 'advanced': 'injected'}))
    assert error.value.error == 'bad_request'
    assert len(responses.calls) == 1


@responses.activate
def test_delete_scans_pages_to_verify_absence(service):
    current = {'name': 'existing'}
    responses.get(BASE + '/getItem/' + UUID, json={'item': current})
    responses.post(BASE + '/delItem/' + UUID, json={'result': 'deleted'})
    responses.post('https://engine.test/api/demo/service/reconfigure', json={'status': 'ok'})
    responses.get(BASE + '/searchItem', json={'rows': [], 'total': 0})
    assert service.mutate(SPEC, dict(action='delete', uuid=UUID, revision=hash_payload(current)))['verified']


@responses.activate
def test_create_and_persistence_only_return_honest_application_status(service):
    responses.get(BASE + '/getItem', json={'item': {'name': ''}})
    responses.post(BASE + '/addItem', json={'result': 'saved', 'uuid': UUID})
    responses.get(BASE + '/getItem/' + UUID, json={'item': {'name': 'new'}})
    result = service.mutate({**SPEC, 'apply': None, 'persistence_only': True}, dict(action='create', values={'name': 'new'}))
    assert result['verified'] and result['config_saved'] and not result['applied']


@responses.activate
@pytest.mark.parametrize('uuid,revision', [('bad', '0' * 64), (UUID, 'bad')])
def test_bad_identity_does_not_contact_upstream(service, uuid, revision):
    with pytest.raises(ManagementError):
        service.mutate(SPEC, dict(action='delete', uuid=uuid, revision=revision))
    assert not responses.calls


@responses.activate
def test_incomplete_delete_listing_cannot_claim_verified(service):
    current = {'name': 'existing'}
    responses.get(BASE + '/getItem/' + UUID, json={'item': current})
    responses.post(BASE + '/delItem/' + UUID, json={'result': 'deleted'})
    responses.post('https://engine.test/api/demo/service/reconfigure', json={'status': 'ok'})
    responses.get(BASE + '/searchItem', json={'rows': [], 'total': 50})
    with pytest.raises(ManagementError) as error:
        service.mutate(SPEC, dict(action='delete', uuid=UUID, revision=hash_payload(current)))
    assert error.value.error == 'unverified' and error.value.partial


@responses.activate
def test_timeout_on_create_is_uncertain_and_never_retried(service):
    from requests.exceptions import Timeout
    responses.get(BASE + '/getItem', json={'item': {'name': ''}})
    responses.post(BASE + '/addItem', body=Timeout('sensitive transport text'))
    with pytest.raises(ManagementError) as error:
        service.mutate(SPEC, dict(action='create', values={'name': 'new'}))
    assert error.value.error == 'timeout' and error.value.partial
    assert 'sensitive' not in str(error.value)
    assert sum(call.request.method == 'POST' for call in responses.calls) == 1


@responses.activate
def test_multiple_options_and_optional_integer_can_be_cleared(service):
    spec = {**SPEC, 'fields': [*SPEC['fields'], dict(name='peers', kind='select', multiple=True,
             options=[dict(value='a', label='A'), dict(value='b', label='B')])]}
    current = {'name': 'old', 'nested': {'port': '80'}, 'peers': 'a'}
    responses.get(BASE + '/getItem/' + UUID, json={'item': current})
    responses.post(BASE + '/setItem/' + UUID, json={'result': 'saved'})
    responses.post('https://engine.test/api/demo/service/reconfigure', json={'status': 'ok'})
    responses.get(BASE + '/getItem/' + UUID, json={'item': {**current, 'nested': {'port': ''}, 'peers': 'b,a'}})
    assert service.mutate(spec, dict(action='update', uuid=UUID, revision=hash_payload(current),
                                    values={'nested.port': '', 'peers': ['a', 'b']}))['verified']


@responses.activate
def test_autogenerated_unsent_field_does_not_fail_create_readback(service):
    spec = {**SPEC, 'fields': [*SPEC['fields'], dict(name='publickey', kind='text')]}
    responses.get(BASE + '/getItem', json={'item': {'name': '', 'publickey': ''}})
    responses.post(BASE + '/addItem', json={'result': 'saved', 'uuid': UUID})
    responses.post('https://engine.test/api/demo/service/reconfigure', json={'status': 'ok'})
    responses.get(BASE + '/getItem/' + UUID, json={'item': {'name': 'new', 'publickey': 'generated'}})
    assert service.mutate(spec, dict(action='create', values={'name': 'new'}))['verified']


@responses.activate
def test_secondary_audit_failure_is_exposed(service, monkeypatch):
    responses.get(BASE + '/getItem', json={'item': {'name': ''}})
    responses.post(BASE + '/addItem', json={'result': 'saved', 'uuid': UUID})
    responses.post('https://engine.test/api/demo/service/reconfigure', json={'status': 'failed'})
    append = service.audit.append
    def fail_after_started(entry):
        if entry.result != 'started':
            raise OSError('disk')
        append(entry)
    monkeypatch.setattr(service.audit, 'append', fail_after_started)
    with pytest.raises(ManagementError) as error:
        service.mutate(SPEC, dict(action='create', values={'name': 'new'}))
    assert error.value.as_dict()['audit_failure'] is True
    assert error.value.partial and error.value.stage == 'apply'


SINGLETON = {**SPEC, 'singleton': True, 'search': None, 'add': None, 'delete': None,
             'get': 'get', 'set': 'set'}


@responses.activate
def test_singleton_list_and_defaults_have_fixed_identity_revision(service):
    current = {'name': 'configuration', 'password': 'hidden'}
    responses.get(BASE + '/get', json={'item': current})
    result = service.list(SINGLETON)
    assert result['total'] == 1 and result['rows'][0]['uuid'] == SINGLETON_UUID
    detail = service.detail(SINGLETON)
    assert detail['revision'] == hash_payload(current)
    assert detail['item']['uuid'] == SINGLETON_UUID
    assert all(call.request.url == BASE + '/get' for call in responses.calls)
    assert 'hidden' not in json.dumps(detail)


@responses.activate
def test_singleton_update_uses_no_uuid_path_and_preserves_unknowns(service):
    current = {'name': 'old', 'password': 'hidden', 'advanced': 'preserved'}
    responses.get(BASE + '/get', json={'item': current})
    responses.post(BASE + '/set', json={'result': 'saved'})
    responses.post('https://engine.test/api/demo/service/reconfigure', json={'status': 'ok'})
    responses.get(BASE + '/get', json={'item': {**current, 'name': 'new'}})
    result = service.mutate(SINGLETON, dict(action='update', uuid=SINGLETON_UUID,
        revision=hash_payload(current), values={'name': 'new', 'password': ''}))
    assert result['verified'] and result['uuid'] == SINGLETON_UUID
    payload = json.loads(responses.calls[1].request.body)
    assert payload['item']['advanced'] == 'preserved' and payload['item']['password'] == 'hidden'
    assert all(SINGLETON_UUID not in call.request.url for call in responses.calls)


@responses.activate
@pytest.mark.parametrize('action', ['create', 'delete'])
def test_singleton_rejects_non_update_without_request(service, action):
    with pytest.raises(ManagementError) as error:
        service.mutate(SINGLETON, dict(action=action, uuid=SINGLETON_UUID, revision='0' * 64))
    assert error.value.status == 405 and not responses.calls


@responses.activate
def test_singleton_stale_revision_does_not_post(service):
    responses.get(BASE + '/get', json={'item': {'name': 'concurrent'}})
    with pytest.raises(ManagementError) as error:
        service.mutate(SINGLETON, dict(action='update', uuid=SINGLETON_UUID, revision='0' * 64, values={'name': 'new'}))
    assert error.value.error == 'conflict'
    assert len(responses.calls) == 1


@responses.activate
def test_singleton_rejects_other_identity_without_request(service):
    with pytest.raises(ManagementError):
        service.detail(SINGLETON, UUID)
    with pytest.raises(ManagementError):
        service.mutate(SINGLETON, dict(action='update', uuid=UUID, revision='0' * 64, values={'name': 'new'}))
    assert not responses.calls


@responses.activate
def test_search_phrase_is_passed_as_encoded_query(service):
    from urllib.parse import parse_qs, urlsplit
    responses.get(BASE + '/searchItem', json={'rows': [], 'total': 0})
    service.list(SPEC, page=2, row_count=25, search='vpn & office')
    query = parse_qs(urlsplit(responses.calls[0].request.url).query)
    assert query == {'current': ['2'], 'rowCount': ['25'], 'searchPhrase': ['vpn & office']}


@responses.activate
@pytest.mark.parametrize('search', ['x' * 257, '\x00', 123])
def test_invalid_search_is_rejected_before_request(service, search):
    with pytest.raises(ManagementError):
        service.list(SPEC, search=search)
    assert not responses.calls


@responses.activate
def test_generated_blank_is_not_sent_or_compared(service):
    spec = {**SPEC, 'fields': [*SPEC['fields'], dict(name='pubkey', kind='text', generated=True, readonly=True)]}
    responses.get(BASE + '/getItem', json={'item': {'name': '', 'pubkey': ''}})
    responses.post(BASE + '/addItem', json={'result': 'saved', 'uuid': UUID})
    responses.post('https://engine.test/api/demo/service/reconfigure', json={'status': 'ok'})
    responses.get(BASE + '/getItem/' + UUID, json={'item': {'name': 'new', 'pubkey': 'generated'}})
    assert service.mutate(spec, dict(action='create', values={'name': 'new', 'pubkey': ''}))['verified']
    assert 'pubkey' not in json.loads(responses.calls[1].request.body)['item']


@responses.activate
def test_validation_only_exposes_allowlisted_field_names(service):
    responses.get(BASE + '/getItem', json={'item': {'name': ''}})
    responses.post(BASE + '/addItem', json={'validations': {
        'item.name': 'private diagnostic', 'password': 'private value',
        'private-key-injected': 'private text', 'unknown': 'private unknown'}})
    with pytest.raises(ManagementError) as error:
        service.mutate(SPEC, dict(action='create', values={'name': 'new'}))
    assert error.value.as_dict()['validations'] == {
        'name': 'Valor rechazado por OPNsense', 'password': 'Valor rechazado por OPNsense'}
    assert 'private' not in json.dumps(error.value.as_dict())


@responses.activate
def test_readback_secret_mismatch_has_identity_but_no_sensitive_contents(service):
    current = {'name': 'old', 'password': 'original-private-value'}
    responses.get(BASE + '/getItem/' + UUID, json={'item': current})
    responses.post(BASE + '/setItem/' + UUID, json={'result': 'saved'})
    responses.post('https://engine.test/api/demo/service/reconfigure', json={'status': 'ok'})
    responses.get(BASE + '/getItem/' + UUID, json={'item': {**current, 'password': 'wrong-private-value'}})
    with pytest.raises(ManagementError) as error:
        service.mutate(SPEC, dict(action='update', uuid=UUID, revision=hash_payload(current), values={'password': ''}))
    result = error.value.as_dict()
    assert result['error'] == 'unverified' and result['uuid'] == UUID and result['partial']
    assert 'private-value' not in json.dumps(result)
    assert 'password' not in json.dumps(result)


@responses.activate
def test_create_empty_option_defaults_and_unknown_metadata_are_not_submitted(service):
    spec = {**SPEC, 'fields': [*SPEC['fields'], dict(name='peers', kind='select', multiple=True)]}
    responses.get(BASE + '/getItem', json={'item': {'name': '', 'peers': {}, 'servers': {}, 'derived': 'metadata'}})
    responses.post(BASE + '/addItem', json={'result': 'saved', 'uuid': UUID})
    responses.post('https://engine.test/api/demo/service/reconfigure', json={'status': 'ok'})
    responses.get(BASE + '/getItem/' + UUID, json={'item': {'name': 'new', 'peers': {}}})
    assert service.mutate(spec, dict(action='create', values={'name': 'new', 'peers': []}))['verified']
    sent = json.loads(responses.calls[1].request.body)['item']
    assert sent == {'name': 'new', 'peers': ''}


@responses.activate
def test_update_empty_option_defaults_normalized_but_unknown_values_preserved(service):
    current = {'name': 'old', 'servers': {}, 'advanced': 'preserved'}
    responses.get(BASE + '/getItem/' + UUID, json={'item': current})
    responses.post(BASE + '/setItem/' + UUID, json={'result': 'saved'})
    responses.post('https://engine.test/api/demo/service/reconfigure', json={'status': 'ok'})
    responses.get(BASE + '/getItem/' + UUID, json={'item': {**current, 'name': 'new'}})
    assert service.mutate(SPEC, dict(action='update', uuid=UUID, revision=hash_payload(selected(current)), values={'name': 'new'}))['verified']
    sent = json.loads(responses.calls[1].request.body)['item']
    assert sent['servers'] == '' and sent['advanced'] == 'preserved'


@responses.activate
def test_numeric_option_arrays_and_empty_lists_are_canonical(service):
    spec = {**SPEC, 'fields': [dict(name='name', kind='text'), dict(name='version', kind='select'), dict(name='peers', kind='select', multiple=True)]}
    raw = {'name': '', 'peers': [], 'version': [{'value': 'Both', 'selected': 1}, {'value': 'IKEv1', 'selected': 0}]}
    responses.get(BASE + '/getItem', json={'item': raw})
    detail = service.detail(spec)
    assert detail['item']['version'] == '0' and detail['item']['peers'] == ''
    assert detail['fields'][1]['options'] == [{'value': '0', 'label': 'Both'}, {'value': '1', 'label': 'IKEv1'}]
    responses.post(BASE + '/addItem', json={'result': 'saved', 'uuid': UUID})
    responses.post('https://engine.test/api/demo/service/reconfigure', json={'status': 'ok'})
    responses.get(BASE + '/getItem/' + UUID, json={'item': {**raw, 'name': 'new'}})
    assert service.mutate(spec, dict(action='create', values={'name': 'new', 'version': '0', 'peers': []}))['verified']
    assert json.loads(responses.calls[2].request.body)['item']['peers'] == ''


@responses.activate
@pytest.mark.parametrize('ack,success', [
    ({'status': 'ok', 'template': 'OK', 'result': 'Control file syntax OK'}, True),
    ({'status': 'failed', 'template': 'OK', 'result': 'Control file syntax OK'}, False),
    ({'status': 'ok', 'template': 'ERROR', 'result': 'Control file syntax OK'}, False),
    ({'status': 'ok', 'template': 'OK', 'result': 'syntax bad'}, False),
])
def test_catalog_specific_apply_ack_is_strict(service, ack, success):
    spec = {**SPEC, 'apply_ack': {'status': ['ok'], 'template': ['OK'], 'result': ['Control file syntax OK']}}
    responses.get(BASE + '/getItem', json={'item': {'name': ''}})
    responses.post(BASE + '/addItem', json={'result': 'saved', 'uuid': UUID})
    responses.post('https://engine.test/api/demo/service/reconfigure', json=ack)
    if success:
        responses.get(BASE + '/getItem/' + UUID, json={'item': {'name': 'new'}})
        assert service.mutate(spec, dict(action='create', values={'name': 'new'}))['verified']
    else:
        with pytest.raises(ManagementError) as error:
            service.mutate(spec, dict(action='create', values={'name': 'new'}))
        assert error.value.stage == 'apply' and error.value.partial
