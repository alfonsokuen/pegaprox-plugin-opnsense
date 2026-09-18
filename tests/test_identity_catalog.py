"""HTTP contract fixtures, not live identity/certificate qualification."""
import json

import pytest
import responses

from src.client import OPNsenseClient, OPNsenseHost
from src.management.engine import ManagementError, ManagementService, selected
from src.management.identity_catalog import IDENTITY_PENDING, IDENTITY_RESOURCES
from src.writers.audit import AuditLog, hash_payload

UUID = '22222222-2222-4222-8222-222222222222'
BASE = 'https://identity.test'


@pytest.fixture
def service(tmp_path):
    return ManagementService(OPNsenseClient(OPNsenseHost(name='identity-fixture', url=BASE,
        api_key='fixture-key', api_secret='fixture-secret')), AuditLog(str(tmp_path / 'audit.jsonl')))


def test_uuid_identity_crud_is_enabled_and_pending_is_explicit():
    assert set(IDENTITY_RESOURCES) == {'auth_groups', 'auth_users', 'trust_cas', 'trust_certificates'}
    for key, spec in IDENTITY_RESOURCES.items():
        assert spec['ha_safe'] is False and spec['qualification'] == 'contract_only'
        assert spec['add'] == 'add' and spec['set'] == 'set' and spec['delete'] == 'del'
    assert 'trust_crls' in IDENTITY_PENDING


@responses.activate
@pytest.mark.parametrize('resource,key', [('auth_users', 'user'), ('trust_cas', 'ca'), ('trust_certificates', 'cert')])
def test_identity_reads_never_expose_sensitive_or_unknown_fields(service, resource, key):
    spec = IDENTITY_RESOURCES[resource]
    raw = {'name': 'fixture-name', 'descr': 'fixture-description', 'uuid': UUID,
           'password': 'sensitive-hash', 'otp_seed': 'sensitive-seed', 'otp_uri': 'sensitive-uri',
           'apikeys': {'key': 'sensitive-key'}, 'authorizedkeys': 'sensitive-ssh',
           'prv': 'sensitive-private', 'prv_payload': 'sensitive-pem', 'private_key': 'sensitive-once'}
    responses.get(BASE + spec['base'] + '/search', json={'rows': [raw], 'total': 1})
    responses.get(BASE + spec['base'] + '/get/' + UUID, json={key: raw})
    assert 'sensitive-' not in json.dumps(service.list(spec))
    assert 'sensitive-' not in json.dumps(service.detail(spec, UUID))
    assert all(call.request.method == 'GET' for call in responses.calls)


def _pem_material(ca=False):
    from datetime import datetime, timedelta, timezone
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    name = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, 'qa.example.test')])
    now = datetime.now(timezone.utc)
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now).not_valid_after(now + timedelta(days=10))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True).sign(key, hashes.SHA256()))
    csr = x509.CertificateSigningRequestBuilder().subject_name(name).sign(key, hashes.SHA256())
    return (certificate.public_bytes(serialization.Encoding.PEM).decode(),
            key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode(),
            csr.public_bytes(serialization.Encoding.PEM).decode())


@responses.activate
@pytest.mark.parametrize('resource,mode', [('trust_cas', 'internal'), ('trust_cas', 'existing'),
    ('trust_certificates', 'internal'), ('trust_certificates', 'import'), ('trust_certificates', 'external')])
def test_certificate_lifecycle_verifies_real_pem_and_never_returns_private_keys(service, resource, mode):
    spec = IDENTITY_RESOURCES[resource]
    crt, prv, csr = _pem_material(ca=resource == 'trust_cas')
    base = BASE + spec['base']
    responses.get(base + '/get', json={spec['key']: {'descr': '', 'action': 'internal', 'lifetime': '10', 'private_key_location': 'firewall'}})
    responses.post(base + '/add', json={'result': 'saved', 'uuid': UUID, 'private_key': 'never-forward-upstream-secrets'})
    responses.get(base + '/get/' + UUID, json={spec['key']: {'descr': 'test cert', 'crt_payload': crt,
        'prv_payload': prv, 'csr_payload': csr, 'commonname': 'qa.example.test'}})
    values = {'descr': 'test cert', 'action': mode, 'commonname': 'qa.example.test', 'lifetime': 10, 'key_type': '1024'}
    if mode in ('existing', 'import'):
        values.update(crt_payload=crt, prv_payload=prv)
    result = service.mutate(spec, dict(action='create', values=values))
    assert result['verified'] and result['config_saved']
    assert 'PRIVATE KEY' not in json.dumps(result) and 'never-forward' not in json.dumps(result)
    from pathlib import Path
    assert 'PRIVATE KEY' not in Path(service.audit.path).read_text()


@responses.activate
def test_certificate_invalid_pem_prevents_mutation(service):
    spec = IDENTITY_RESOURCES['trust_certificates']
    responses.get(BASE + spec['base'] + '/get', json={'cert': {'descr': '', 'action': 'internal'}})
    with pytest.raises(ManagementError) as error:
        service.mutate(spec, dict(action='create', values={'descr': 'invalid', 'action': 'import', 'crt_payload': 'sensitive-invalid-pem'}))
    assert error.value.error == 'bad_request'
    assert 'sensitive' not in str(error.value)
    assert all(call.request.method == 'GET' for call in responses.calls)


@responses.activate
def test_generated_certificate_mismatched_key_is_partial_failure(service):
    spec = IDENTITY_RESOURCES['trust_certificates']
    crt, _, _ = _pem_material()
    _, wrong_key, _ = _pem_material()
    responses.get(BASE + spec['base'] + '/get', json={'cert': {'descr': '', 'action': 'internal'}})
    responses.post(BASE + spec['base'] + '/add', json={'result': 'saved', 'uuid': UUID})
    responses.get(BASE + spec['base'] + '/get/' + UUID, json={'cert': {'descr': 'test', 'crt_payload': crt, 'prv_payload': wrong_key}})
    with pytest.raises(ManagementError) as error:
        service.mutate(spec, dict(action='create', values={'descr': 'test', 'action': 'internal', 'commonname': 'qa.example.test', 'lifetime': 10, 'key_type': '1024'}))
    assert error.value.error == 'unverified' and error.value.uuid == UUID and error.value.partial
    assert 'PRIVATE KEY' not in json.dumps(error.value.as_dict())


@responses.activate
def test_trust_edit_defaults_are_safe_and_private_key_export_is_not_offered(service):
    spec = IDENTITY_RESOURCES['trust_certificates']
    responses.get(BASE + spec['base'] + '/get/' + UUID, json={'cert': {'descr': 'stored',
        'action': {'reissue': {'value': 'Reissue', 'selected': 1}, 'manual': {'value': 'Manual', 'selected': 0}},
        'private_key_location': {'firewall': {'value': 'Firewall', 'selected': 1}, 'local': {'value': 'Download', 'selected': 0}}}})
    detail = service.detail(spec, UUID)
    assert detail['item']['action'] == 'manual'
    field = next(field for field in detail['fields'] if field['name'] == 'private_key_location')
    assert field['options'] == [{'value': 'firewall', 'label': 'Firewall'}]


@responses.activate
def test_trust_manual_update_preserves_private_key_and_verifies_certificate(service):
    spec = IDENTITY_RESOURCES['trust_certificates']
    crt, prv, _ = _pem_material()
    current = {'descr': 'old', 'action': 'reissue', 'crt_payload': crt, 'prv_payload': prv}
    base = BASE + spec['base']
    responses.get(base + '/get/' + UUID, json={'cert': current})
    responses.post(base + '/set/' + UUID, json={'result': 'saved'})
    responses.get(base + '/get/' + UUID, json={'cert': {**current, 'descr': 'new'}})
    result = service.mutate(spec, dict(action='update', uuid=UUID, revision=hash_payload(selected(current)),
        values={'descr': 'new', 'action': 'manual', 'prv_payload': ''}))
    assert result['verified']
    assert json.loads(responses.calls[1].request.body)['cert']['prv_payload'] == prv
    assert 'PRIVATE KEY' not in json.dumps(result)


@responses.activate
@pytest.mark.parametrize('resource', ['auth_groups', 'auth_users', 'trust_cas', 'trust_certificates'])
def test_identity_delete_verifies_absence(service, resource):
    spec = IDENTITY_RESOURCES[resource]
    current = {'name': 'owned-fixture', 'descr': 'owned-fixture'}
    base = BASE + spec['base']
    responses.get(base + '/get/' + UUID, json={spec['key']: current})
    responses.post(base + '/del/' + UUID, json={'result': 'deleted'})
    responses.get(base + '/search', json={'rows': [], 'total': 0})
    assert service.mutate(spec, dict(action='delete', uuid=UUID, revision=hash_payload(current)))['verified']


@responses.activate
def test_import_private_key_mismatch_is_rejected_before_post(service):
    spec = IDENTITY_RESOURCES['trust_certificates']
    crt, _, _ = _pem_material()
    _, wrong, _ = _pem_material()
    responses.get(BASE + spec['base'] + '/get', json={'cert': {'descr': '', 'action': 'internal'}})
    with pytest.raises(ManagementError) as error:
        service.mutate(spec, dict(action='create', values={'descr': 'bad import', 'action': 'import', 'crt_payload': crt, 'prv_payload': wrong}))
    assert error.value.error == 'bad_request'
    assert all(call.request.method == 'GET' for call in responses.calls)


@responses.activate
def test_group_create_and_update_use_native_wrappers_and_saved_not_service_applied(service):
    spec = IDENTITY_RESOURCES['auth_groups']
    base = BASE + spec['base']
    defaults = {'name': '', 'description': '', 'priv': [], 'member': [], 'scope': 'user', 'gid': ''}
    responses.get(base + '/get', json={'group': defaults})
    responses.post(base + '/add', json={'result': 'saved', 'uuid': UUID})
    saved = {**defaults, 'name': 'qa_group', 'gid': '2999'}
    responses.get(base + '/get/' + UUID, json={'group': saved})
    created = service.mutate(spec, dict(action='create', values={'name': 'qa_group', 'priv': [], 'member': []}))
    assert created['verified'] and created['config_saved'] and not created['applied']
    sent = json.loads(responses.calls[1].request.body)['group']
    assert sent['priv'] == sent['member'] == '' and 'gid' not in sent and 'scope' not in sent
    responses.get(base + '/get/' + UUID, json={'group': saved})
    responses.post(base + '/set/' + UUID, json={'result': 'saved'})
    responses.get(base + '/get/' + UUID, json={'group': {**saved, 'description': 'updated'}})
    # Explicit prior canonical revision, never the UID/GID as path identity.
    updated = service.mutate(spec, dict(action='update', uuid=UUID,
        revision=hash_payload(selected(saved)), values={'description': 'updated'}))
    assert updated['verified'] and not updated['applied']


@responses.activate
@pytest.mark.parametrize('password,changed', [('', False), ('new-fixture-password', True)])
def test_user_password_is_write_only_and_blank_update_omits_it(service, password, changed):
    spec = IDENTITY_RESOURCES['auth_users']
    base = BASE + spec['base']
    current = {'name': 'qa_disabled', 'password': '', 'disabled': '1', 'uid': '2999', 'scope': 'user'}
    responses.get(base + '/get/' + UUID, json={'user': current})
    responses.post(base + '/set/' + UUID, json={'result': 'saved'})
    result = service.mutate(spec, dict(action='update', uuid=UUID,
        revision=hash_payload(selected(current)), values={'password': password, 'disabled': True}))
    sent = json.loads(responses.calls[1].request.body)['user']
    if changed:
        assert sent['password'] == password
        assert result['secret_change_acknowledged'] is True and result['secret_verified'] is False
    else:
        assert 'password' not in sent and 'secret_change_acknowledged' not in result
    assert 'new-fixture-password' not in json.dumps(result)
    assert result['verified'] and not result['applied']


@responses.activate
def test_user_create_requires_password_and_can_verify_other_fields(service):
    spec = IDENTITY_RESOURCES['auth_users']
    base = BASE + spec['base']
    responses.get(base + '/get', json={'user': {'name': '', 'password': '', 'disabled': '0'}})
    with pytest.raises(ManagementError) as error:
        service.mutate(spec, dict(action='create', values={'name': 'qa_disabled', 'password': ''}))
    assert error.value.error == 'bad_request'
    assert all(call.request.method == 'GET' for call in responses.calls)
    responses.post(base + '/add', json={'result': 'saved', 'uuid': UUID})
    responses.get(base + '/get/' + UUID, json={'user': {'name': 'qa_disabled', 'password': '', 'disabled': '1'}})
    result = service.mutate(spec, dict(action='create', values={'name': 'qa_disabled', 'password': 'fixture-password', 'disabled': True}))
    assert result['verified'] and result['secret_verified'] is False


@responses.activate
def test_stale_user_revision_never_changes_password(service):
    spec = IDENTITY_RESOURCES['auth_users']
    responses.get(BASE + spec['base'] + '/get/' + UUID, json={'user': {'name': 'qa', 'password': '', 'pwd_changed_at': 'new'}})
    with pytest.raises(ManagementError) as error:
        service.mutate(spec, dict(action='update', uuid=UUID, revision='0' * 64, values={'password': 'fixture-password'}))
    assert error.value.error == 'conflict'
    assert len(responses.calls) == 1
