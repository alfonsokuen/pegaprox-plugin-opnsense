import base64
import json
import os
from pathlib import Path

import pytest
import requests
import responses

from src.client import OPNsenseHost
from src.management.backups import BackupStore, MAX_XML
from src.management.engine import ManagementError
from src.writers.audit import AuditLog

BASE = 'https://backup.test'
URL = BASE + '/api/core/backup/download/this'
XML = b'<opnsense><system><hostname>lab</hostname><password>SECRET</password></system></opnsense>'


@pytest.fixture
def store(tmp_path):
    return BackupStore(tmp_path / 'state' / 'backups', AuditLog(str(tmp_path / 'audit.jsonl')), 'admin')


def host():
    return OPNsenseHost('Lab firewall', BASE, 'PRIVATE_KEY', 'PRIVATE_SECRET')


def remote(payload=XML, status=200, **kwargs):
    responses.get(URL, body=payload, status=status, content_type='application/octet-stream', **kwargs)


@responses.activate
def test_roundtrip_encrypted_authenticated_metadata_and_audit(store):
    assert not store.key_path.exists()
    assert store.list() == []
    assert not store.key_path.exists()
    remote()
    metadata = store.create(host())
    file = store.root / (metadata['id'] + '.enc')
    assert b'SECRET' not in file.read_bytes() and b'<opnsense>' not in file.read_bytes()
    assert len(store.key_path.read_bytes()) == 32
    assert metadata['source'] == 'latest_historical_backup'
    assert store.read(metadata['id']) == XML
    assert store.restore_decrypt(metadata['id']) == XML
    assert store.list() == [metadata]
    log = Path(store.audit.path).read_text()
    assert 'SECRET' not in log and '<opnsense>' not in log
    assert ['backup.create', 'backup.download', 'backup.download'] == [
        json.loads(line)['action'] for line in log.splitlines()]
    assert store.delete(metadata['id'])['deleted']
    assert store.list() == []
    if os.name != 'nt':
        assert store.key_path.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize('part', ['ciphertext', 'nonce', 'metadata', 'key'])
@responses.activate
def test_corruption_wrong_key_and_metadata_tampering_fail_closed(store, part):
    remote()
    metadata = store.create(host())
    file = store.root / (metadata['id'] + '.enc')
    envelope = json.loads(file.read_bytes())
    if part == 'key':
        store.key_path.write_bytes(b'x' * 32)
    elif part == 'metadata':
        envelope['metadata']['host'] = 'changed'
    else:
        data = bytearray(base64.b64decode(envelope[part]))
        data[0] ^= 1
        envelope[part] = base64.b64encode(data).decode()
    file.write_text(json.dumps(envelope))
    with pytest.raises(ManagementError) as error:
        store.read(metadata['id'])
    assert error.value.status == 409 and 'SECRET' not in str(error.value)


@pytest.mark.parametrize('ident', ['../backups.key', '..', '/tmp/key', 'C:\\key', 'x.enc', '', None])
def test_path_traversal_rejected_without_key_creation(store, ident):
    for method in (store.read, store.delete):
        with pytest.raises(ManagementError) as error:
            method(ident)
        assert error.value.status == 400
    assert not store.key_path.exists()


@pytest.mark.parametrize('payload', [b'', b'<html>login</html>', b'<pfsense/>', b'<opnsense>',
    b'<!DOCTYPE opnsense [<!ENTITY secret SYSTEM "file:///etc/passwd">]><opnsense>&secret;</opnsense>',
    b'<!DOCTYPE opnsense><opnsense/>'])
@responses.activate
def test_invalid_xml_never_creates_key_or_encrypted_file(store, payload):
    remote(payload)
    with pytest.raises(ManagementError):
        store.create(host())
    assert not store.key_path.exists() and list(store.root.iterdir()) == []


@pytest.mark.parametrize('status', [302, 401, 403, 404, 500])
@responses.activate
def test_remote_failure_never_leaks_body_or_credentials(store, status):
    remote(b'PRIVATE_SECRET', status, headers={'Location': 'https://evil.test'})
    with pytest.raises(ManagementError) as error:
        store.create(host())
    assert 'PRIVATE' not in str(error.value)
    assert len(responses.calls) == 1
    assert not store.key_path.exists()


@responses.activate
def test_remote_timeout_is_sanitized_and_not_retried(store):
    responses.get(URL, body=requests.Timeout('PRIVATE_SECRET'))
    with pytest.raises(ManagementError) as error:
        store.create(host())
    assert error.value.error == 'timeout' and 'PRIVATE' not in str(error.value)
    assert len(responses.calls) == 1


@responses.activate
def test_size_limit_rejects_declared_oversized_response(store):
    remote(headers={'Content-Length': str(MAX_XML + 1)})
    with pytest.raises(ManagementError):
        store.create(host())
    assert not store.key_path.exists()


@responses.activate
def test_missing_key_is_never_silently_replaced_for_existing_backups(store):
    remote()
    store.create(host())
    store.key_path.unlink()
    with pytest.raises(ManagementError):
        store.create(host())
    assert not store.key_path.exists()


@responses.activate
def test_audit_failure_prevents_remote_download(store, monkeypatch):
    def fail(_entry):
        raise OSError('SECRET')
    monkeypatch.setattr(store.audit, 'append', fail)
    with pytest.raises(ManagementError) as error:
        store.create(host())
    assert error.value.error == 'audit'
    assert not responses.calls


@responses.activate
def test_repeated_backups_reuse_key_but_have_unique_nonce(store):
    remote()
    first = store.create(host())
    key = store.key_path.read_bytes()
    second = store.create(host())
    assert store.key_path.read_bytes() == key
    one = json.loads((store.root / (first['id'] + '.enc')).read_bytes())
    two = json.loads((store.root / (second['id'] + '.enc')).read_bytes())
    assert one['nonce'] != two['nonce'] and one['ciphertext'] != two['ciphertext']


def test_changed_target_directory_is_rejected(store):
    store.root.rename(store.root.with_name('old'))
    store.root.mkdir()
    with pytest.raises(ManagementError):
        store.list()


@responses.activate
def test_size_limit_also_counts_actual_stream_bytes(store):
    remote(b'x' * (MAX_XML + 1))
    with pytest.raises(ManagementError):
        store.create(host())
    assert not store.key_path.exists()


@responses.activate
def test_transport_respects_host_tls_and_timeout_and_disables_redirects(store, monkeypatch):
    remote()
    observed = {}
    original = requests.Session.get
    def capture(session, url, **kwargs):
        observed.update(kwargs)
        return original(session, url, **kwargs)
    monkeypatch.setattr(requests.Session, 'get', capture)
    store.create(OPNsenseHost('lab', BASE, 'key', 'secret', verify_tls=False,
                             connect_timeout=2, read_timeout=7))
    assert observed['verify'] is False
    assert observed['timeout'] == (2, 7)
    assert observed['allow_redirects'] is False and observed['stream'] is True
