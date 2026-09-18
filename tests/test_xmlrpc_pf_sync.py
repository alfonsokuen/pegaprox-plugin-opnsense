"""XMLRPC scope/direction guards and uncertain post-apply outcomes."""
from copy import deepcopy

import pytest

from src.client import OPNsenseError, OPNsenseTimeoutError
from src.routes.firewall import parse_payload
from src.writers.audit import AuditLog, hash_payload
from src.writers.verified import VerifiedFirewallWriter
from tests.test_firewall_management import Firewall, DNAT, UUID


class HANode(Firewall):
    def __init__(self, primary):
        super().__init__()
        self.primary = primary
        self.ha = {"synchronizetoip": "198.18.12.3" if primary else "", "syncitems": "aliases,rules,nat"}
        self.ip = "198.18.12.2" if primary else "198.18.12.3"
        self.role = "MASTER" if primary else "BACKUP"
        self.peer = None
        self.trigger_error = None

    def get(self, path, **params):
        if path.endswith('/hasync/get'):
            return {"hasync": deepcopy(self.ha)}
        if path.endswith('/getInterfaceConfig'):
            return {"sync": {"ipv4": [{"ipaddr": self.ip}]},
                    "lan": {"ipv4": [{"ipaddr": "198.18.11.1", "vhid": "201"}]}}
        if path.endswith('/getVipStatus'):
            return {"rows": [{"vhid": "201", "subnet": "198.18.11.1", "status": self.role}]}
        return super().get(path, **params)

    def post(self, path, payload):
        result = super().post(path, payload)
        if path.endswith('/restart/pf'):
            if self.trigger_error:
                if isinstance(self.trigger_error, Exception):
                    raise self.trigger_error
                return self.trigger_error
            self.peer.rows = deepcopy(self.rows)
        return result


@pytest.fixture
def writer(tmp_path):
    a, b = HANode(True), HANode(False)
    a.peer = b
    return VerifiedFirewallWriter(a, AuditLog(str(tmp_path/'audit.jsonl')), 'port_forward',
                                  peer=b, ha_sync_mode='xmlrpc_pf', ha_verify_backoff=0)


def test_apply_does_not_replicate_until_explicit_pf_sync(writer):
    out = writer.execute('create', parse_payload('port_forward', DNAT))
    assert out['ok'] and out['sync']['triggered'] and out['sync']['verified']
    assert writer.peer.rows == writer.client.rows
    assert sum(path.endswith('/restart/pf') for _, path, _ in writer.client.calls) == 1


@pytest.mark.parametrize('target', ['198.18.99.9', '198.18.12.2', '198.18.11.1',
    'http://198.18.12.3', 'https://user:secret@198.18.12.3', 'https://198.18.12.3/other',
    'https://198.18.12.3?x=1', 'peer.example', '', None])
def test_unsafe_target_has_no_mutation(writer, target):
    writer.client.ha['synchronizetoip'] = target
    out = writer.execute('create', parse_payload('port_forward', DNAT))
    assert not out['ok'] and out['error'] == 'ha_unsafe'
    assert not any(method == 'POST' for method, _, _ in writer.client.calls)
    assert 'secret' not in str(out)


@pytest.mark.parametrize('sections', ['aliases,rules,nat,users', 'aliases,rules', '', 'nat,'])
def test_unsafe_scope_has_no_mutation(writer, sections):
    writer.client.ha['syncitems'] = sections
    out = writer.execute('create', parse_payload('port_forward', DNAT))
    assert out['error'] == 'ha_unsafe' and not writer.client.rows


def test_reverse_direction_has_no_mutation(writer):
    writer.peer.ha['synchronizetoip'] = '198.18.12.2'
    assert writer.execute('create', parse_payload('port_forward', DNAT))['error'] == 'ha_unsafe'
    assert not writer.client.rows


@pytest.mark.parametrize('failure', [OPNsenseTimeoutError('uncertain'), {'status': 'error'}])
def test_sync_failure_never_retries_or_rolls_back_applied_create(writer, failure):
    writer.client.trigger_error = failure
    out = writer.execute('create', parse_payload('port_forward', DNAT))
    assert out['applied'] and out['verified'] and out['error'] == 'ha_unverified'
    assert not out['rollback']['attempted'] and UUID in writer.client.rows
    assert sum(path.endswith('/restart/pf') for _, path, _ in writer.client.calls) == 1


def test_failover_after_apply_prevents_trigger(writer):
    post = writer.client.post
    def change_role(path, payload):
        out = post(path, payload)
        if path.endswith('/apply'):
            writer.client.role = 'BACKUP'
            writer.peer.role = 'MASTER'
        return out
    writer.client.post = change_role
    out = writer.execute('create', parse_payload('port_forward', DNAT))
    assert out['error'] == 'ha_unverified' and out['applied']
    assert not out['sync']['triggered'] and not out['rollback']['attempted']


def prepare_last_delete(writer):
    payload = parse_payload('port_forward', DNAT)
    writer.client.rows[UUID] = deepcopy(payload['rule'])
    writer.peer.rows[UUID] = deepcopy(payload['rule'])
    post = writer.client.post
    def legacy_merge(path, body):
        if path.endswith('/restart/pf'):
            writer.client.calls.append(('POST', path, body))
            return {'status': 'ok'}  # nat/outbound exists, nat/rule omitted: peer retains it.
        return post(path, body)
    writer.client.post = legacy_merge
    return hash_payload(payload['rule'])


def test_last_dnat_delete_reconciles_known_unchanged_peer_uuid(writer):
    revision = prepare_last_delete(writer)
    out = writer.execute('delete', uuid=UUID, revision=revision)
    assert out['ok'] and out['sync']['peer_cleanup']['verified']
    assert not writer.client.rows and not writer.peer.rows
    assert [path for method, path, _ in writer.peer.calls if method == 'POST'] == [
        '/api/firewall/d_nat/delRule/'+UUID, '/api/firewall/d_nat/apply']
    assert 'peer_cleanup=' in out['audit']['detail']


def test_last_dnat_divergence_prevents_local_delete(writer):
    revision = prepare_last_delete(writer)
    writer.peer.rows[UUID]['target'] = '192.0.2.99'
    out = writer.execute('delete', uuid=UUID, revision=revision)
    assert out['error'] == 'conflict' and UUID in writer.client.rows
    assert not any(method == 'POST' for method, _, _ in writer.client.calls)


def test_last_dnat_peer_edit_after_local_delete_is_not_destroyed(writer):
    revision = prepare_last_delete(writer)
    post = writer.client.post
    def change_peer(path, body):
        out = post(path, body)
        if path.endswith('/restart/pf'):
            writer.peer.rows[UUID]['target'] = '192.0.2.99'
        return out
    writer.client.post = change_peer
    out = writer.execute('delete', uuid=UUID, revision=revision)
    assert out['error'] == 'ha_unverified'
    assert not out['sync']['peer_cleanup']['attempted']
    assert writer.peer.rows[UUID]['target'] == '192.0.2.99'


def test_last_dnat_peer_timeout_never_retries(writer):
    revision = prepare_last_delete(writer)
    writer.peer.fail['delRule'] = OPNsenseTimeoutError('uncertain peer delete')
    out = writer.execute('delete', uuid=UUID, revision=revision)
    assert out['error'] == 'ha_unverified' and not out['rollback']['attempted']
    assert sum('delRule' in path for method, path, _ in writer.peer.calls if method == 'POST') == 1


def test_last_dnat_extra_peer_rule_prevents_mutation(writer):
    revision = prepare_last_delete(writer)
    writer.peer.rows['ea100c16-cdf8-43fd-8a2b-b39207655326'] = deepcopy(writer.peer.rows[UUID])
    out = writer.execute('delete', uuid=UUID, revision=revision)
    assert out['error'] == 'conflict' and UUID in writer.client.rows


def test_last_dnat_incomplete_peer_listing_prevents_mutation(writer):
    revision = prepare_last_delete(writer)
    get = writer.peer.get
    writer.peer.get = lambda path, **kw: {'rows': [], 'total': 1} if 'search' in path else get(path, **kw)
    out = writer.execute('delete', uuid=UUID, revision=revision)
    assert not out['ok'] and UUID in writer.client.rows


def test_last_dnat_carp_change_after_trigger_prevents_peer_delete(writer):
    revision = prepare_last_delete(writer)
    post = writer.client.post
    def failover(path, payload):
        out = post(path, payload)
        if path.endswith('/restart/pf'):
            writer.peer.role = 'MASTER'
        return out
    writer.client.post = failover
    out = writer.execute('delete', uuid=UUID, revision=revision)
    assert out['error'] == 'ha_unverified' and not out['sync']['peer_cleanup']['attempted']
    assert not any(method == 'POST' for method, _, _ in writer.peer.calls)


def test_synthetic_lockout_rows_cannot_hide_incomplete_dnat_listing(writer):
    writer.peer.get = lambda *args, **kwargs: {'rows': [{'uuid': 'lockout_0'}], 'total': 1}
    with pytest.raises(OPNsenseError, match='incomplete'):
        writer.verify(UUID, None, writer.peer)


@pytest.mark.parametrize('total', [None, 'invalid', {}, True, -1, 0.5])
def test_malformed_peer_total_after_delete_preserves_applied_result(writer, total):
    writer.ha_sync_mode = 'automatic'
    payload = parse_payload('port_forward', DNAT)['rule']
    writer.client.rows[UUID] = deepcopy(payload)
    get = writer.peer.get
    writer.peer.get = lambda path, **kw: {'rows': [], 'total': total} if 'search' in path else get(path, **kw)
    out = writer.execute('delete', uuid=UUID, revision=hash_payload(payload))
    assert out['error'] == 'ha_unverified' and out['applied'] and out['verified']
    assert out['uuid'] == UUID and out['audit']['result'] == 'error'
    assert 'invalid total' in out['sync']['detail']
    assert not out['rollback']['attempted'] and not writer.client.rows
    assert len(writer.audit.tail()) == 2
    assert sum('delRule' in path for method, path, _ in writer.client.calls if method == 'POST') == 1


@pytest.mark.parametrize('field', ['vhid', 'advskew'])
def test_malformed_carp_after_apply_preserves_result_and_prevents_trigger(writer, field):
    get = writer.client.get
    def malformed_after_apply(path, **kw):
        out = get(path, **kw)
        if path.endswith('/getVipStatus') and writer.client.rows:
            out['rows'][0][field] = 'invalid'
        return out
    writer.client.get = malformed_after_apply
    out = writer.execute('create', parse_payload('port_forward', DNAT))
    assert out['error'] == 'ha_unverified' and out['applied'] and out['verified']
    assert out['uuid'] == UUID and out['audit']['result'] == 'error'
    assert not out['sync']['triggered'] and not out['rollback']['attempted']
    assert UUID in writer.client.rows and len(writer.audit.tail()) == 2
